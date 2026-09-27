Challenge 2: Automated Safe Evidence Replay Build a stateful execution module that 
validates a theoretical attack path by chaining a series of safe, idempotent HTTP requests (e.g., 
GET requests) against an authorized staging API. The module must automatically extract state 
variables (like JWTs or Object IDs) from step one's response and inject them into step two's 
request to definitively prove the chained exploitability (e.g., Broken Object Level Authorization 
leading to data exposure) rather than relying solely on static assumptions. 
Expected Outcome: 
● A working module that takes a correlated attack path and safely executes actual API 
calls to validate the connection. 
● Demonstrated ability to parse state or tokens from one API response and dynamically 
build the subsequent request in the chain. 
● An evidence log or visual flag proving the vulnerability path is genuinely exploitable in 
the live environment, thereby minimizing false positives.
