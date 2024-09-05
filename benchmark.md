# Simple Benchmark Results

- The survey is an average of 10 sets of iterations

## Non-secure TCP

|    |        1B|      1KiB|        1MiB|        1GiB|
|----|----------|----------|------------|------------|
|   1| 0.32353ms| 0.18129ms|   0.93892ms| 557.88663ms|
|  10| 0.56151ms| 0.30156ms|   5.59655ms|Not measured|
| 100| 2.22849ms| 0.59126ms|  45.54506ms|Not measured|
|1000|10.54374ms| 4.19835ms| 493.30166ms|Not measured|

## Secure Session

|    |        1B|      1KiB|        1MiB|        1GiB|
|----|----------|----------|------------|------------|
|   1| 0.37744ms| 0.66717ms|  12.65319ms|3938.79333ms|
|  10| 1.29402ms| 1.46742ms|  62.29613ms|Not measured|
| 100| 5.14847ms| 6.39509ms| 462.04218ms|Not measured|
|1000|17.25438ms|23.51131ms|4417.58897ms|Not measured|

## Performance under the same conditions

|    |        1B|      1KiB|        1MiB|        1GiB|
|----|----------|----------|------------|------------|
|   1| 85.70%   | 27.18%   |  7.42%     |  14.17%    |
|  10| 43.38%   | 20.55%   |  8.98%     |Not measured|
| 100| 43.31%   | 9.24%    |  9.85%     |Not measured|
|1000| 61.11%   | 17.85%   | 11.17%     |Not measured|

- *If you are interested, please benchmark by increasing the number of trials*
- *Also, experiment in a real network environment rather than a local host*