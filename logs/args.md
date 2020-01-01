
USAGE: python strace-parser.py [ARG] [FILES]

ARG:
- table - prints trace info for each parsed line/event (includes unfinished and resumed events)
- ftable - prints final trace info
- json - prints trace as a json to be used by falcon-solver (includes similarity comparison between other messages)
- mean - prints means related to message size
- match - prints similarity stats comparing different block sizes
