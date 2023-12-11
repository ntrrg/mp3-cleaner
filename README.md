```shell-session
mp3-cleaner - clean and reduce music files.

Usage: mp3-cleaner [<options>] <destination> <source>...

Options:
  -b=<rate>, --bit-rate=<rate> (128|192|320) (default: 128) (id: bit_rate)
    Output audio bit rate.
  --log-file=<file> (id: log_file)
    Use given file as log file.
  --log-format=<format> (ctxlog|json) (default: ctxlog) (id: log_format)
    Use given format as log encoding format.
  --log-level=<level> (debug|info|warn|error|fatal|disabled) (id: log_level)
    Minimum severity for log records.
  --env-file[=<file>] (default: .env) (id: env_file)
    Read environment variables from the given file.
  --help[=<option_id>] (id: help)
    Print this help message.
  --version (id: version)
    Print version number.

Environment variables:
  - BIT_RATE (id: bit_rate): Output audio bit rate.
  - LOG_FILE (id: log_file): Use given file as log file.
  - LOG_FORMAT (id: log_format): Use given format as log encoding format.
  - LOG_LEVEL (id: log_level): Minimum severity for log records.

Copyright (c) 2023 Miguel Angel Rivera Notararigo
Released under the MIT License
```

This program executes this command programatically in a bunch of MP3 files:

```shell-session
ffmpeg -i <input file> -y -filter:v scale=w=500:h=500,format=yuvj420p -c:v mjpeg -c:a libmp3lame -ab <bit rate> <output file>
```
