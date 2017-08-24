package world.jawair.sencrypt

import java.util.Base64

import scala.util.Try

/**
  * Holds the cipher text and the IV used during the encryption process.
  *
  * @author Ali Hosseiny
  */
case class CipherText(cipherText: Array[Byte], iv: Array[Byte]) {

  def decrypt(secretKey: SecretKey): Try[String] = secretKey.decrypt(this)

  def encodeCipher: String = CipherText.base64Encoder.encodeToString(cipherText)

  def encodeIv: String = CipherText.base64Encoder.encodeToString(iv)

  def encode: String = s"$encodeCipher:$encodeIv"
}

object CipherText {

  private val base64Encoder = Base64.getUrlEncoder
  private val base64Decoder = Base64.getUrlDecoder

  def apply(cipherText: String, iv: String): CipherText = {
    CipherText(base64Decoder.decode(cipherText), base64Decoder.decode(iv))
  }

  def decode(encoded: String): Try[CipherText] = Try {
    val parts = encoded.split(":")
    assume(parts.length == 2, "The encode encrypted text must be of the form CIPHER:IV")

    CipherText(parts(0), parts(1))
  }
}
