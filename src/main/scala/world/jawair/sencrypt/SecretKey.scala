package world.jawair.sencrypt

import java.security.SecureRandom
import java.util.Base64
import javax.crypto.spec.{GCMParameterSpec, PBEKeySpec, SecretKeySpec}
import javax.crypto.{Cipher, SecretKeyFactory}

import scala.util.Try

/**
  * A [[SecretKey]] instance can be used to encrypt strings or to decrypt from an instance of [[CipherText]]
  * @author Ali Hosseiny
  */
case class SecretKey(secretKeySpec: SecretKeySpec, salt: Array[Byte]) {

  def encrypt(text: String, mode: String = "AES/GCM/NoPadding"): CipherText = {
    val cipher = Cipher.getInstance(mode)
    cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec)

    CipherText(cipher.doFinal(text.getBytes("UTF-8")), cipher.getIV)
  }

  def decrypt(encryptedText: CipherText, mode: String = "AES/GCM/NoPadding"): Try[String] = {
    val cipher = Cipher.getInstance(mode)
    cipher.init(Cipher.DECRYPT_MODE, secretKeySpec, new GCMParameterSpec(SecretKey.keySize, encryptedText.iv))

    Try(new String(cipher.doFinal(encryptedText.cipherText), "UTF-8"))
  }

  def saltAsString: String = SecretKey.base64Encoder.encodeToString(salt)
}

object SecretKey {

  private val base64Encoder = Base64.getUrlEncoder
  private val base64Decoder = Base64.getUrlDecoder

  private val iterationCount = 65536
  private val keySize        = 128

  private val factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256")

  def apply(secretKeySpec: SecretKeySpec, salt: String): SecretKey = {
    SecretKey(secretKeySpec, base64Decoder.decode(salt))
  }

  def generate(password: String): SecretKey = {
    val salt: Array[Byte] = new Array[Byte](keySize / 8)
    SecureRandom.getInstanceStrong.nextBytes(salt)

    of(password, salt)
  }

  /**
    *
    * @param password A user-chosed strong password
    * @param salt A Base64 encoded salt
    * @return
    */
  def of(password: String, salt: String): SecretKey = {
    of(password, base64Decoder.decode(salt))
  }

  def of(password: String, salt: Array[Byte]): SecretKey = {
    val spec =
      new PBEKeySpec(password.toCharArray, salt, iterationCount, keySize)
    val tmp = factory.generateSecret(spec)
    SecretKey(new SecretKeySpec(tmp.getEncoded, "AES"), salt)
  }

  /**
    * Generates a salt of the specified size (in bytes) using a strong instance of SecureRandom and encodes it in Base64
    *
    * @param size Size in bytes of the salt
    * @return Salt encoded in Base64 (URL-safe mode)
    */
  def generateSalt(size: Int): String = {
    val salt: Array[Byte] = new Array[Byte](size)
    SecureRandom.getInstanceStrong.nextBytes(salt)

    base64Encoder.encodeToString(salt)
  }
}
