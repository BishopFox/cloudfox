package models

type GenericIterator[T any] interface {
	Next() (*T, error)
}
