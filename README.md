# Sigma Protocols

Conext:

https://medium.com/@loveshharchandani/zero-knowledge-proofs-with-sigma-protocols-91e94858a1fb

## Sigma Protocol Steps

A Sigma protocol follows these three steps:

- *Commitment*: The prover generates a random number, creates a commitment to that randomness, and sends the commitment to the verifier.
- *Challenge*: After getting the commitment, the verifier generates a random number as a challenge and sends it to the prover. It is important that the verifier does not send the challenge before getting the commitment or else the prover can cheat.
- *Response*: The prover takes the challenge and creates a response using the random number chosen in step 1, the challenge, and the witness. The prover will then send the response to the verifier, who will do some computation and will or will not be convinced of the knowledge of the witness.