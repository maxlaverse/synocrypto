package log

type Logger interface {
	Error(args ...interface{})
	Errorf(format string, args ...interface{})
	Warning(args ...interface{})
	Warningf(format string, args ...interface{})
	Info(args ...interface{})
	Infof(format string, args ...interface{})
	Debug(args ...interface{})
	Debugf(format string, args ...interface{})
}

var l Logger = noopLogger{}

func SetLogger(lg Logger)                         { l = lg }
func Error(args ...interface{})                   { l.Error(args...) }
func Errorf(format string, args ...interface{})   { l.Errorf(format, args...) }
func Warning(args ...interface{})                 { l.Warning(args...) }
func Warningf(format string, args ...interface{}) { l.Warningf(format, args...) }
func Info(args ...interface{})                    { l.Info(args...) }
func Infof(format string, args ...interface{})    { l.Infof(format, args...) }
func Debug(args ...interface{})                   { l.Debug(args...) }
func Debugf(format string, args ...interface{})   { l.Debugf(format, args...) }

type noopLogger struct{}

func (n noopLogger) Error(args ...interface{})                   {}
func (n noopLogger) Errorf(format string, args ...interface{})   {}
func (n noopLogger) Warning(args ...interface{})                 {}
func (n noopLogger) Warningf(format string, args ...interface{}) {}
func (n noopLogger) Info(args ...interface{})                    {}
func (n noopLogger) Infof(format string, args ...interface{})    {}
func (n noopLogger) Debug(args ...interface{})                   {}
func (n noopLogger) Debugf(format string, args ...interface{})   {}
