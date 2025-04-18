// Package common implements shared functions and structs between various book* applications
package common

import (
	"encoding/json"
	"fmt"
	"math/rand"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/flomesh-io/fsm/pkg/logger"
	"github.com/flomesh-io/fsm/pkg/utils"
)

// BookBuyerPurchases is all of the books that the bookbuyer has bought
type BookBuyerPurchases struct {
	BooksBought   int64 `json:"booksBought"`
	BooksBoughtV1 int64 `json:"booksBoughtV1"`
	BooksBoughtV2 int64 `json:"booksBoughtV2"`
}

// BookThiefThievery is all of the books the bookthief has stolen
type BookThiefThievery struct {
	BooksStolen   int64 `json:"booksStolen"`
	BooksStolenV1 int64 `json:"booksStolenV1"`
	BooksStolenV2 int64 `json:"booksStolenV2"`
}

// BookStorePurchases are all of the books sold from the bookstore
type BookStorePurchases struct {
	BooksSold int64 `json:"booksSold"`
}

const (
	// RestockWarehouseURL is a header string constant.
	RestockWarehouseURL = "restock-books"

	// bookstorePort is the bookstore service's port
	bookstorePort = 14001

	// bookwarehousePort is the bookwarehouse service's port
	bookwarehousePort = 14001

	httpPrefix = "http://"

	httpsPrefix = "https://"
)

var (
	// enableEgress determines whether egress is enabled
	enableEgress = os.Getenv(EnableEgressEnvVar) == "true"

	sleepDurationBetweenRequestsSecondsStr = utils.GetEnv("CI_SLEEP_BETWEEN_REQUESTS_SECONDS", "1")
	minSuccessThresholdStr                 = utils.GetEnv("CI_MIN_SUCCESS_THRESHOLD", "1")
	maxIterationsStr                       = utils.GetEnv("CI_MAX_ITERATIONS_THRESHOLD", "0") // 0 for unlimited
	bookstoreServiceName                   = utils.GetEnv("BOOKSTORE_SVC", "bookstore")
	warehouseServiceName                   = utils.GetEnv("WAREHOUSE_SVC", "bookwarehouse")
	bookstoreNamespace                     = utils.GetEnv(BookstoreNamespaceEnvVar, "bookstore")
	bookwarehouseNamespace                 = utils.GetEnv(BookwarehouseNamespaceEnvVar, "bookwarehouse")

	// Due to a limitation on kubernetes on Windows we need to use the FQDN
	// otherwise DNS will not be able to resolve it.
	// https://kubernetes.io/docs/setup/production-environment/windows/intro-windows-in-kubernetes/#dns-limitations
	bookstoreService = fmt.Sprintf("%s.%s.svc.cluster.local:%d", bookstoreServiceName, bookstoreNamespace, bookstorePort)
	warehouseService = fmt.Sprintf("%s.%s.svc.cluster.local:%d", warehouseServiceName, bookwarehouseNamespace, bookwarehousePort)
	booksBought      = fmt.Sprintf("http://%s/books-bought", bookstoreService)
	buyBook          = fmt.Sprintf("http://%s/buy-a-book/new", bookstoreService)
	chargeAccountURL = fmt.Sprintf("http://%s/%s", warehouseService, RestockWarehouseURL)

	interestingHeaders = []string{
		IdentityHeader,
		BooksBoughtHeader,
		"Server",
		"Date",
	}

	urlHeadersMap = map[string]map[string]string{
		booksBought: {
			"client-app": "bookbuyer", // this is a custom header
			"user-agent": "Go-http-client/1.1",
		},
		buyBook: nil,
	}

	egressURLs = []string{
		"edition.cnn.com",
		"github.com",
	}
)

var log = logger.NewPretty("demo")

// RestockBooks restocks the bookstore with certain amount of books from the warehouse.
func RestockBooks(amount int, headers map[string]string) {
	log.Info().Msgf("Restocking from book warehouse with %d books", amount)

	client := &http.Client{}
	requestBody := strings.NewReader(strconv.Itoa(1))
	req, err := http.NewRequest("POST", chargeAccountURL, requestBody)
	req.Host = (fmt.Sprintf("%s.%s", warehouseServiceName, bookwarehouseNamespace))

	for k, v := range headers {
		req.Header.Set(k, v)
	}

	if err != nil {
		log.Error().Err(err).Msgf("RestockBooks: error posting to %s", chargeAccountURL)
		return
	}

	log.Info().Msgf("RestockBooks: Posted to %s with headers %v", req.URL, req.Header)

	resp, err := client.Do(req)
	if err != nil {
		log.Error().Err(err).Msgf("RestockBooks: Error posting to %s", chargeAccountURL)
		return
	}

	//nolint: errcheck
	//#nosec G307
	defer resp.Body.Close()
	for _, hdr := range interestingHeaders {
		log.Info().Msgf("RestockBooks (%s) adding header {%s: %s}", chargeAccountURL, hdr, getHeader(resp.Header, hdr))
	}
	log.Info().Msgf("RestockBooks (%s) finished w/ status: %s %d ", chargeAccountURL, resp.Status, resp.StatusCode)
}

// GetBooks reaches out to the bookstore and buys/steals books. This is invoked by the bookbuyer and the bookthief.
func GetBooks(participantName string, meshExpectedResponseCode int, booksCount *int64, booksCountV1 *int64, booksCountV2 *int64) {
	minSuccessThreshold, maxIterations, sleepDurationBetweenRequests := getEnvVars(participantName)

	// The URLs this participant will attempt to query from the bookstore service
	urlSuccessMap := map[string]bool{
		booksBought: false,
		buyBook:     false,
	}

	if enableEgress {
		urlSuccessMap[httpPrefix] = false
		urlSuccessMap[httpsPrefix] = false
	}

	urlExpectedRespCode := map[string]int{
		booksBought: meshExpectedResponseCode,
		buyBook:     meshExpectedResponseCode,
		// Using only prefixes as placeholders so that we can select random URL while testing
		httpPrefix:  getHTTPEgressExpectedResponseCode(),
		httpsPrefix: getHTTPSEgressExpectedResponseCode(),
	}

	// Count how many times we have reached out to the bookstore
	var iteration int64

	// Count how many times BOTH urls have returned the expected status code
	var successCount int64

	// Keep state of the previous success/failure so we know when things regress
	previouslySucceeded := false

	for {
		timedOut := maxIterations > 0 && iteration >= maxIterations
		iteration++

		fmt.Printf("\n\n--- %s:[ %d ] -----------------------------------------\n", participantName, iteration)

		startTime := time.Now()

		for url := range urlSuccessMap {
			fetchURL := url

			// Create random URLs to test egress
			if fetchURL == httpPrefix || fetchURL == httpsPrefix {
				index := rand.Intn(len(egressURLs)) // #nosec G404
				fetchURL = fmt.Sprintf("%s%s", url, egressURLs[index])
			}

			// We only care about the response code of the HTTP(s) call for the given URL
			responseCode, identity := fetch(fetchURL)

			expectedResponseCode := urlExpectedRespCode[url]
			succeeded := responseCode == expectedResponseCode
			if !succeeded {
				fmt.Printf("ERROR: response code for %q is %d;  expected %d\n", url, responseCode, expectedResponseCode)
			}
			urlSuccessMap[url] = succeeded

			// Regardless of what expect the response to be (depends on the policy) - in case of 200 OK - increase book counts.
			if responseCode == http.StatusOK {
				if url == buyBook {
					if strings.HasPrefix(identity, "bookstore-v1") {
						atomic.AddInt64(booksCountV1, 1)
						atomic.AddInt64(booksCount, 1)
						log.Info().Msgf("BooksCountV1=%d", booksCountV1)
					} else if strings.HasPrefix(identity, "bookstore-v2") {
						atomic.AddInt64(booksCountV2, 1)
						atomic.AddInt64(booksCount, 1)
						log.Info().Msgf("BooksCountV2=%d", booksCountV2)
					}
				}
			}

			// We are looking for a certain number of sequential successful HTTP requests.
			if previouslySucceeded && allUrlsSucceeded(urlSuccessMap) {
				successCount++
				goalReached := successCount >= minSuccessThreshold
				if goalReached && !timedOut {
					// Sending this string to STDOUT will inform the CI Maestro that this is a succeeded;
					// Maestro will stop tailing logs.
					fmt.Println(Success)
					log.Debug().Msgf("%s - Iteration: %d", Success, iteration)
				}
			}

			if previouslySucceeded && !succeeded {
				// This is a regression. We had success previously, but now we are seeing a failure.
				// Reset the success counter.
				successCount = 0
			}

			// Keep track of the previous state so we can track a) sequential successes and b) regressions.
			previouslySucceeded = allUrlsSucceeded(urlSuccessMap)
		}

		if timedOut {
			// We are over budget!
			fmt.Printf("Threshold of %d iterations exceeded\n\n", maxIterations)
			fmt.Print(Failure)
			log.Error().Msgf("%s, Threshold of %d iterations exceeded", Failure, maxIterations)
		}

		fillerTime := sleepDurationBetweenRequests - time.Since(startTime)
		if fillerTime > 0 {
			time.Sleep(fillerTime)
		}
	}
}

func allUrlsSucceeded(urlSucceeded map[string]bool) bool {
	success := true
	for _, succeeded := range urlSucceeded {
		success = success && succeeded
	}
	return success
}

func fetch(url string) (responseCode int, identity string) {
	headersMap := urlHeadersMap[url]

	client := &http.Client{}
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		fmt.Printf("Error requesting %s: %s\n", url, err)
	}

	for headerKey, headerValue := range headersMap {
		req.Header.Add(headerKey, headerValue)
	}

	fmt.Printf("\nFetching %s\n", req.URL)
	fmt.Printf("Request Headers: %v\n", req.Header)
	resp, err := client.Do(req)
	if err != nil {
		fmt.Printf("Error fetching %s: %s\n", url, err)
	} else {
		//nolint: errcheck
		//#nosec G307
		defer resp.Body.Close()
		responseCode = resp.StatusCode
		for _, hdr := range interestingHeaders {
			fmt.Printf("%s: %s\n", hdr, getHeader(resp.Header, hdr))
		}
		fmt.Printf("Status: %s\n", resp.Status)
	}
	identity = "unknown"
	if resp != nil && resp.Header != nil {
		identity = getHeader(resp.Header, IdentityHeader)
	}

	return responseCode, identity
}

func getHeader(headers map[string][]string, header string) string {
	val, ok := headers[header]
	if !ok {
		val = []string{"n/a"}
	}
	return strings.Join(val, ", ")
}

func getEnvVars(participantName string) (minSuccessThreshold int64, maxIterations int64, sleepDurationBetweenRequests time.Duration) {
	log := logger.New(fmt.Sprintf("demo/%s", participantName))

	var err error

	minSuccessThreshold, err = strconv.ParseInt(minSuccessThresholdStr, 10, 32)
	if err != nil {
		log.Fatal().Err(err).Msgf("Error parsing integer environment variable %q", minSuccessThresholdStr)
	}

	maxIterations, err = strconv.ParseInt(maxIterationsStr, 10, 32)
	if err != nil {
		log.Fatal().Err(err).Msgf("Error parsing integer environment variable %q", maxIterationsStr)
	}

	sleepDurationBetweenRequestsInt, err := strconv.ParseInt(sleepDurationBetweenRequestsSecondsStr, 10, 32)
	if err != nil {
		log.Fatal().Err(err).Msgf("Error parsing integer environment variable %q", sleepDurationBetweenRequestsSecondsStr)
	}

	return minSuccessThreshold, maxIterations, time.Duration(sleepDurationBetweenRequestsInt) * time.Second
}

// GetExpectedResponseCodeFromEnvVar returns the expected response code based on the given environment variable
func GetExpectedResponseCodeFromEnvVar(envVar, defaultValue string) int {
	expectedRespCodeStr := utils.GetEnv(envVar, defaultValue)
	expectedRespCode, err := strconv.ParseInt(expectedRespCodeStr, 10, 0)
	if err != nil {
		log.Fatal().Err(err).Msgf("Could not convert environment variable %s='%s' to int", envVar, expectedRespCodeStr)
	}
	return int(expectedRespCode)
}

// getHTTPSEgressExpectedResponseCode returns the expected response code for HTTPS egress.
// Since HTTPS egress depends on clients to originate TLS, when egress is disabled the
// TLS negotiation will fail. As a result no HTTP response code will be returned
// but rather the HTTP library will return 0 as the status code in such cases.
func getHTTPSEgressExpectedResponseCode() int {
	if enableEgress {
		return http.StatusOK
	}

	return 0
}

// getHTTPEgressExpectedResponseCode returns the expected response code for HTTP egress
func getHTTPEgressExpectedResponseCode() int {
	if enableEgress {
		return http.StatusOK
	}

	return http.StatusNotFound
}

// GetRawGenerator returns a function that can be used to write a response of book data
func GetRawGenerator(books interface{}) func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		booksRaw, err := json.Marshal(books)
		if err != nil {
			log.Fatal().Err(err).Msg("Failed to marshal book data")
		}
		_, err = w.Write(booksRaw)
		if err != nil {
			log.Fatal().Err(err).Msg("Failed to write raw output")
		}
	}
}

// GetTracingHeaderKeys returns header keys used for distributed tracing with Jaeger
func GetTracingHeaderKeys() []string {
	return []string{"X-Ot-Span-Context", "X-Request-Id", "uber-trace-id", "x-b3-traceid", "x-b3-spanid", "x-b3-parentspanid"}
}

// GetTracingHeaders gets the tracing related header values from a request
func GetTracingHeaders(r *http.Request) map[string]string {
	var headers = map[string]string{}
	for _, key := range GetTracingHeaderKeys() {
		if v := r.Header.Get(key); v != "" {
			headers[key] = v
		}
	}

	return headers
}
