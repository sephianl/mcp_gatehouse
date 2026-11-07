[
  import_deps: [:ash, :ash_ai, :plug],
  plugins: [Spark.Formatter, Styler],
  inputs: ["{mix,.formatter,.credo}.exs", "{config,lib,test}/**/*.{ex,exs}"]
]
