package fixture

// AppConfig exercises: nested structs, mixed public/secret, default tags, pointer-to-struct.
type AppConfig struct {
	DatabaseURL      string   `mapstructure:"db_url"`
	DatabasePassword string   `mapstructure:"db_password"`
	LogLevel         string   `mapstructure:"log_level" sauce:"public"`
	Port             int      `mapstructure:"port" sauce:"public" default:"8080"`
	Debug            bool     `mapstructure:"debug" sauce:"public"`
	APIKey           string   `mapstructure:"api_key"`
	JWTSecret        string   `mapstructure:"jwt_secret"`
	Server           Server   `mapstructure:"server"`
	Metrics          *Metrics `mapstructure:"metrics"`
}

type Server struct {
	Host         string `mapstructure:"host" sauce:"public" default:"0.0.0.0"`
	ReadTimeout  int    `mapstructure:"read_timeout" sauce:"public" default:"30"`
	WriteTimeout int    `mapstructure:"write_timeout" sauce:"public" default:"30"`
	TLSCert      string `mapstructure:"tls_cert"`
	TLSKey       string `mapstructure:"tls_key"`
}

// Metrics exercises pointer-to-struct traversal.
type Metrics struct {
	Enabled  bool   `mapstructure:"enabled" sauce:"public" default:"false"`
	Endpoint string `mapstructure:"endpoint" sauce:"public" default:"/metrics"`
}

// AllSecretConfig exercises the path where no public fields exist (no ConfigMap generated).
type AllSecretConfig struct {
	DBPassword string `mapstructure:"db_password"`
	APIKey     string `mapstructure:"api_key"`
	JWTSecret  string `mapstructure:"jwt_secret"`
}

// AllPublicConfig exercises the path where no secrets exist (no ExternalSecret generated).
type AllPublicConfig struct {
	LogLevel string `mapstructure:"log_level" sauce:"public"`
	Port     int    `mapstructure:"port" sauce:"public" default:"8080"`
	Debug    bool   `mapstructure:"debug" sauce:"public"`
}

// SquashConfig exercises the mapstructure squash behavior.
type SquashConfig struct {
	Base    BaseConfig `mapstructure:",squash"`
	Feature string     `mapstructure:"feature_flag" sauce:"public"`
}

type BaseConfig struct {
	AppName  string `mapstructure:"app_name" sauce:"public"`
	LogLevel string `mapstructure:"log_level" sauce:"public"`
	Secret   string `mapstructure:"secret_key"`
}
