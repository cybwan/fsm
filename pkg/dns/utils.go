package dns

func makeQuestionCache(maxCount int) *MemoryQuestionCache {
	return &MemoryQuestionCache{Backend: make([]QuestionCacheEntry, 0), Maxcount: maxCount}
}
