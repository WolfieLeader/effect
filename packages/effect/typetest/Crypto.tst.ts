import { Crypto, Effect } from "effect"
import { describe, expect, it } from "tstyche"

describe("Crypto", () => {
  const implementation = {
    randomBytes: (size: number) => new Uint8Array(size),
    digest: (_algorithm: Crypto.DigestAlgorithm, data: Uint8Array) => Effect.succeed(data),
    hmac: (_algorithm: Crypto.HmacAlgorithm, _key: Uint8Array, data: Uint8Array) => Effect.succeed(data),
    pbkdf2: (
      _algorithm: Crypto.HmacAlgorithm,
      _password: Uint8Array,
      _salt: Uint8Array,
      _iterations: number,
      length: number
    ) => Effect.succeed(new Uint8Array(length)),
    rsaOaepEncrypt: (options: Crypto.RsaOaepOptions) => Effect.succeed(options.data)
  }

  it("requires all cryptographic operations on the service", () => {
    expect<Crypto.Crypto>().type.toBeAssignableTo<
      Required<Pick<Crypto.Crypto, "hmac" | "pbkdf2" | "rsaOaepEncrypt">>
    >()
  })

  it("requires all cryptographic operations in the constructor", () => {
    expect(Crypto.make).type.toBeCallableWith(implementation)
    expect(Crypto.make).type.not.toBeCallableWith({
      randomBytes: implementation.randomBytes,
      digest: implementation.digest,
      pbkdf2: implementation.pbkdf2,
      rsaOaepEncrypt: implementation.rsaOaepEncrypt
    })
    expect(Crypto.make).type.not.toBeCallableWith({
      randomBytes: implementation.randomBytes,
      digest: implementation.digest,
      hmac: implementation.hmac,
      rsaOaepEncrypt: implementation.rsaOaepEncrypt
    })
    expect(Crypto.make).type.not.toBeCallableWith({
      randomBytes: implementation.randomBytes,
      digest: implementation.digest,
      hmac: implementation.hmac,
      pbkdf2: implementation.pbkdf2
    })
    expect(Crypto.make).type.not.toBeCallableWith({ ...implementation, hmac: undefined })
    expect(Crypto.make).type.not.toBeCallableWith({ ...implementation, pbkdf2: undefined })
    expect(Crypto.make).type.not.toBeCallableWith({ ...implementation, rsaOaepEncrypt: undefined })
  })
})
