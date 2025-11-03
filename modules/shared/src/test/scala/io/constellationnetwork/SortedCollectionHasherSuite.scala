package io.constellationnetwork

import java.io.{IOException, OutputStream}
import java.security.MessageDigest

import cats.Show
import cats.effect.{IO, Resource}
import cats.syntax.option._

import scala.collection.immutable.{SortedMap, SortedSet}

import io.constellationnetwork.ext.cats.effect.ResourceIO
import io.constellationnetwork.json.JsonSerializer
import io.constellationnetwork.schema.address.Address
import io.constellationnetwork.schema.balance.Balance
import io.constellationnetwork.schema.generators.{addressGen, balanceGen}
import io.constellationnetwork.schema.{showSortedMapAsList, showSortedSetAsList}
import io.constellationnetwork.security.Hasher
import io.constellationnetwork.security.hash.Hash
import io.constellationnetwork.security.hash.Hash.Sha256Digest

import com.aayushatharva.brotli4j.encoder.BrotliOutputStream
import com.aayushatharva.brotli4j.encoder.Encoder.Parameters
import io.circe.syntax.EncoderOps
import io.circe.{Encoder, KeyEncoder, Printer}
import org.scalacheck.Gen
import weaver.MutableIOSuite
import weaver.scalacheck.Checkers

object SortedCollectionHasherSuite extends MutableIOSuite with Checkers {

  type Res = Hasher[IO]

  override def sharedResource: Resource[IO, Res] =
    JsonSerializer.forSync[IO].asResource.map { implicit json =>
      Hasher.forJson[IO]
    }

  test("hash sorted set") { hasher =>
    forall(addressesGen) { addresses =>
      for {
        hash1 <- hasher.hash(addresses)
        hash2 = hashSortedSet(addresses)
      } yield expect.eql(hash1, hash2)
    }
  }

  test("hash sorted map") { hasher =>
    forall(balancesGen) { balances =>
      for {
        hash1 <- hasher.hash(balances)
        hash2 = hashSortedMap(balances)
      } yield expect.eql(hash1, hash2)
    }
  }

  def hashSortedSet[A](content: SortedSet[A])(implicit e: Encoder[A]): Hash = {
    def printer = Printer(dropNullValues = true, indent = "", sortKeys = true)
    val params = new Parameters().setQuality(2)
    val sha256OutputStream = new Sha256OutputStream
    val brotliOutputStream = new BrotliOutputStream(sha256OutputStream, params)
    var bytesSerialized = 0

    def write(s: String): Unit = {
      val bytes = s.getBytes("UTF-8")
      brotliOutputStream.write(bytes)
      bytesSerialized += bytes.length
//      println(bytesSerialized)
    }

    write("[")
    val it = content.iterator
    if (it.hasNext) {
      write(it.next().asJson.printWith(printer))
      while (it.hasNext) {
        write(",")
        write(it.next().asJson.printWith(printer))
      }
    }
    write("]")

    brotliOutputStream.close()
    sha256OutputStream.hash.get
  }

  def hashSortedMap[K, V](content: SortedMap[K, V])(implicit keyEncoder: KeyEncoder[K], valueEncoder: Encoder[V]): Hash = {
    def printer = Printer(dropNullValues = true, indent = "", sortKeys = true)
    val params = new Parameters().setQuality(2)
    val sha256OutputStream = new Sha256OutputStream
    val brotliOutputStream = new BrotliOutputStream(sha256OutputStream, params)
    var bytesSerialized = 0
    var json = ""

    def write(s: String): Unit = {
      val bytes = s.getBytes("UTF-8")
      brotliOutputStream.write(bytes)
      bytesSerialized += bytes.length
      json += s
      //      println(bytesSerialized)
    }

    def writeMapEntry(entry: (K, V)): Unit = {
      val (key, value) = entry
      write(s""""${keyEncoder(key)}":""")
      write(value.asJson.printWith(printer))
    }

    write("{")
    val it = content.iterator
    if (it.hasNext) {
      writeMapEntry(it.next())
      while (it.hasNext) {
        write(",")
        writeMapEntry(it.next())
      }
    }
    write("}")

    brotliOutputStream.close()
    sha256OutputStream.hash.get
  }

  class Sha256OutputStream extends OutputStream {
    private val sha256 = MessageDigest.getInstance("SHA-256")
    @volatile private var maybeHash = none[Hash]
    private var numWrites = 0
    private var bytesWritten = 0

    override def write(b: Int): Unit = {
      ensureOpen()
      sha256.update((b & 0xff).toByte)
      numWrites += 1
      bytesWritten += 1
//      println(s"#$numWrites: $bytesWritten")
    }

    override def write(b: Array[Byte], off: Int, len: Int): Unit = {
      ensureOpen()
      sha256.update(b, off, len)
      numWrites += 1
      bytesWritten += len
//      println(s"#$numWrites: $bytesWritten")
    }

    override def write(b: Array[Byte]): Unit = {
      ensureOpen()
      sha256.update(b)
      numWrites += 1
      bytesWritten += b.length
//      println(s"#$numWrites: $bytesWritten")
    }

    override def close(): Unit = {
      val digest = Sha256Digest(sha256.digest())
      maybeHash = Hash(digest.toHexString).some
//      println(s"#$numWrites: $bytesWritten")
    }

    def hash: Option[Hash] = maybeHash

    private def ensureOpen(): Unit = if (maybeHash.nonEmpty) throw new IOException("closed")

  }

  implicit val sortedSetAddressShow: Show[SortedSet[Address]] = showSortedSetAsList[Address]
  implicit val sortedMapAddressBalanceShow: Show[SortedMap[Address, Balance]] = showSortedMapAsList[Address, Balance]
  val addressesGen: Gen[SortedSet[Address]] =
    Gen.chooseNum(1, 1024).flatMap(n => Gen.listOfN(n, addressGen).map(list => SortedSet.from(list)))
  val balancesGen: Gen[SortedMap[Address, Balance]] =
    Gen.chooseNum(1, 100).flatMap(n => Gen.listOfN(n, Gen.zip(addressGen, balanceGen)).map(list => SortedMap.from(list)))

}
