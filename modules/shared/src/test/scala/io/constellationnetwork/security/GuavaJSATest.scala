package io.constellationnetwork.security

import io.constellationnetwork.security.hash.Hash

import org.scalatest.funsuite.AnyFunSuite

class GuavaJSATest extends AnyFunSuite {

  test("Guava / JSA MessageDigest.clone() compatibility") {
    val rng = new java.security.SecureRandom()
    val data = Array.ofDim[Byte](1024)
    (1 to 1_000_000).foreach { _ =>
      rng.nextBytes(data)
      val guava = Hash.fromBytes(data)
      val jsa = Hash.fromBytesJSAClone(data)
      assert(guava == jsa)
    }
  }

  test("Guava / JSA MessageDigest.getInstance() compatibility") {
    val rng = new java.security.SecureRandom()
    val data = Array.ofDim[Byte](1024)
    (1 to 1_000_000).foreach { _ =>
      rng.nextBytes(data)
      val guava = Hash.fromBytes(data)
      val jsa = Hash.fromBytesJSAGetInstance(data)
      assert(guava == jsa)
    }
  }

  val data = {
    val array = Array.ofDim[Byte](1024)
    val rng = new java.security.SecureRandom()
    rng.nextBytes(array)
    array
  }

  test("JSA MessageDigest.clone() performance ") {
    timed("MessageDigest.clone()") {
      (1 to 10_000_000).foreach { _ =>
        Hash.fromBytesJSAClone(data)
      }
    }
  }

  test("JSA MessageDigest.getInstance() performance ") {
    timed("MessageDigest.getInstance()") {
      (1 to 10_000_000).foreach { _ =>
        Hash.fromBytesJSAGetInstance(data)
      }
    }
  }

  test("Guava performance") {
    timed("Guava") {
      (1 to 10_000_000).foreach { _ =>
        Hash.fromBytes(data)
      }
    }
  }

  def timed[T](message: String)(f: => T): T = {
    val start = System.currentTimeMillis()
    try
      f
    finally {
      val elapsed = System.currentTimeMillis() - start
      println(s"$message $elapsed ms")
    }
  }

}
