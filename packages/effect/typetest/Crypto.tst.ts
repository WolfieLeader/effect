import { Crypto, Effect, type PlatformError } from "effect"
import { describe, expect, it } from "tstyche"

describe("Crypto", () => {
  const implementation = {
    ...Crypto.makeSubtle({} as SubtleCrypto),
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
      Required<
        Pick<
          Crypto.Crypto,
          | "hmac"
          | "pbkdf2"
          | "rsaOaepEncrypt"
          | "generateSecretKey"
          | "generateKeyPair"
          | "importKey"
          | "exportKey"
          | "encrypt"
          | "decrypt"
          | "sign"
          | "verify"
        >
      >
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
    expect(Crypto.make).type.not.toBeCallableWith({ ...implementation, generateSecretKey: undefined })
    expect(Crypto.make).type.not.toBeCallableWith({ ...implementation, generateKeyPair: undefined })
    expect(Crypto.make).type.not.toBeCallableWith({ ...implementation, importKey: undefined })
    expect(Crypto.make).type.not.toBeCallableWith({ ...implementation, exportKey: undefined })
    expect(Crypto.make).type.not.toBeCallableWith({ ...implementation, encrypt: undefined })
    expect(Crypto.make).type.not.toBeCallableWith({ ...implementation, decrypt: undefined })
    expect(Crypto.make).type.not.toBeCallableWith({ ...implementation, sign: undefined })
    expect(Crypto.make).type.not.toBeCallableWith({ ...implementation, verify: undefined })
  })

  it("infers managed key results and the Crypto service requirement", () => {
    expect(Crypto.generateSecretKey({ name: "AES-GCM", length: 256 })).type.toBe<
      Effect.Effect<Crypto.Key, PlatformError.PlatformError, Crypto.Crypto>
    >()
    expect(Crypto.generateKeyPair({ name: "Ed25519" })).type.toBe<
      Effect.Effect<Crypto.KeyPair, PlatformError.PlatformError, Crypto.Crypto>
    >()
    const key = {} as Crypto.Key
    const data = new Uint8Array()
    expect(Crypto.verify({ name: "Ed25519" }, key, data, data)).type.toBe<
      Effect.Effect<boolean, PlatformError.PlatformError, Crypto.Crypto>
    >()
    expect(Crypto.encrypt({ name: "AES-GCM", iv: data }, key, data)).type.toBe<
      Effect.Effect<Uint8Array, PlatformError.PlatformError, Crypto.Crypto>
    >()
    expect(Crypto.generateSecretKey).type.not.toBeCallableWith({ name: "Ed25519" })
    expect(Crypto.generateKeyPair).type.not.toBeCallableWith({ name: "AES-GCM", length: 256 })
    expect(Crypto.generateSecretKey).type.not.toBeCallableWith({ name: "AES-GCM", length: 64 })
    expect(Crypto.encrypt).type.not.toBeCallableWith({ name: "AES-GCM" }, key, data)
    expect(Crypto.sign).type.not.toBeCallableWith({ name: "ECDSA" }, key, data)
  })
})
