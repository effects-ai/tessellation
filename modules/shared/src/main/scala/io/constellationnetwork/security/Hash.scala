package io.constellationnetwork.security

import java.nio.charset.StandardCharsets
import java.security.MessageDigest

import cats.Show

import io.constellationnetwork.ext.derevo.ordering

import com.google.common.hash.{HashCode, Hashing}
import derevo.cats.{order, show}
import derevo.circe.magnolia.{decoder, encoder}
import derevo.derive
import eu.timepit.refined.auto._
import io.estatico.newtype.macros.newtype
import io.estatico.newtype.ops._
import org.scalacheck.{Arbitrary, Gen}

object hash {

  @derive(encoder, decoder, ordering, order, show)
  @newtype
  case class Hash(value: String) {
    def getBytes: Array[Byte] = value.getBytes(StandardCharsets.UTF_8)
  }

  object Hash {

    def hashCodeFromBytes(bytes: Array[Byte]): HashCode =
      Hashing.sha256().hashBytes(bytes)

    def fromBytes(bytes: Array[Byte]): Hash =
      Hash(hashCodeFromBytes(bytes).toString)

    private val hexDigits = "0123456789abcdef".toCharArray
    private val sha256 = MessageDigest.getInstance("SHA-256")

    def sha256FromBytesClone(bytes: Array[Byte]): Array[Byte] = {
      val md = sha256.clone().asInstanceOf[MessageDigest]
      md.update(bytes)
      md.digest()
    }

    def sha256FromBytesGetInstance(bytes: Array[Byte]): Array[Byte] = {
      val md = MessageDigest.getInstance("SHA-256")
      md.update(bytes)
      md.digest()
    }

    def fromBytesJSAClone(bytes: Array[Byte]): Hash = {
      val sha256Bytes = sha256FromBytesClone(bytes)
      val sha256String = sha256Bytes
        .foldLeft(new StringBuilder(64)) { (sb, b) =>
          sb.append(hexDigits((b >> 4) & 0xf)).append(hexDigits(b & 0xf))
        }
        .toString
      Hash(sha256String)
    }

    def fromBytesJSAGetInstance(bytes: Array[Byte]): Hash = {
      val sha256Bytes = sha256FromBytesGetInstance(bytes)
      val sha256String = sha256Bytes
        .foldLeft(new StringBuilder(64)) { (sb, b) =>
          sb.append(hexDigits((b >> 4) & 0xf)).append(hexDigits(b & 0xf))
        }
        .toString
      Hash(sha256String)
    }

    def empty: Hash = Hash(s"%064d".format(0))

    implicit val arbitrary: Arbitrary[Hash] = Arbitrary(Gen.stringOfN(64, Gen.hexChar).map(Hash(_)))

    val shortShow: Show[Hash] = Show.show[Hash](h => s"Hash(${h.value.take(8)})")
  }

  @derive(encoder, decoder, ordering, order, show)
  @newtype
  case class ProofsHash(value: String)

  object ProofsHash {
    implicit val arbitrary: Arbitrary[ProofsHash] = Arbitrary(
      Arbitrary.arbitrary[Hash].map(h => ProofsHash(h.coerce[String]))
    )
  }

}
