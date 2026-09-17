targetScope = 'subscription'

param valid bool
param failureMessage string

output validated bool = valid ? true : fail(failureMessage)
