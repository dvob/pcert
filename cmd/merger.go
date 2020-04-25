package cmd

// Merger interface is an extension for the value interface. The interface
// indicates that a value can be merged (e.g. slice or maps). Often this is
// also supported with the Set method of the value interface but in addition to
// the Set method the Merge method guarantees that nothing gets overwritten with
// a call to Merge.
type Merger interface {
	Merge(val string) error
}
