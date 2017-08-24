package world.jawair.sencrypt

import scala.util.{Failure, Random, Success}

import org.scalatest._

/**
  *
  * @author Ali Hosseiny
  */
class SecretKeyTest extends WordSpec with Matchers {

  "SecretKey" should {

    "encrypt and decrypt text" in {
      val text = Random.nextString(43)
      val password = Random.nextString(9)

      val secretKey = SecretKey.generate(password)

      secretKey.encrypt(text).decrypt(secretKey) shouldEqual Success(text)
    }

    "fail to decrypt a message with the wrong key password" in {
      val text = Random.nextString(43)
      val password = Random.nextString(9)

      val secretKey = SecretKey.generate(password)
      val secretKey2 = SecretKey.of((password.head + 1) + password.tail, secretKey.salt)

      secretKey.encrypt(text).decrypt(secretKey2).getClass shouldEqual classOf[Failure[_]]
    }

    "generate a different IV each time" in {
      val text = "Hi my name is someone do you hear me 20' ? _:;,.-éà$è"
      val password = "èv¨wkèi0r423 0irft¨è234 "

      val secretKey = SecretKey.generate(password)

      val encryptedText1 = secretKey.encrypt(text)
      val encryptedText2 = secretKey.encrypt(text)
      val encryptedText3 = secretKey.encrypt(text)

      encryptedText1.iv should not equal encryptedText2.iv
      encryptedText2.iv should not equal encryptedText3.iv
    }
  }
}
