package io.constellationnetwork.dag.l1.domain.block

import cats.effect.kernel.Async
import cats.syntax.applicative._
import cats.syntax.eq._
import cats.syntax.functor._
import cats.syntax.traverse._

import io.constellationnetwork.schema.Block.HashedOps
import io.constellationnetwork.schema.transaction.TransactionReference
import io.constellationnetwork.schema.{Block, BlockReference}
import io.constellationnetwork.security.signature.Signed
import io.constellationnetwork.security.{Hashed, Hasher}

object BlockRelations {

  def dependsOn[F[_]: Async](
    blocks: Hashed[Block],
    txHasher: Hasher[F]
  )(block: Signed[Block]): F[Boolean] = dependsOn[F](Set(blocks), txHasher = txHasher)(block)

  def dependsOn[F[_]: Async](
    blocks: Set[Hashed[Block]],
    references: Set[BlockReference] = Set.empty,
    txHasher: Hasher[F]
  )(block: Signed[Block]): F[Boolean] = {
    def dstAddresses = blocks.flatMap(_.transactions.toSortedSet.toList.map(_.value.destination))

    def isChild =
      block.parent.exists(parentRef => (blocks.map(_.ownReference) ++ references).exists(_ === parentRef))
    def hasReferencedAddress = block.transactions.map(_.source).exists(srcAddress => dstAddresses.exists(_ === srcAddress))
    def hasReferencedTx = blocks.toList
      .flatTraverse(_.transactions.toSortedSet.toList.traverse { tx =>
        implicit val hasher = txHasher
        TransactionReference.of(tx)
      })
      .map(_.toSet)
      .map { txRefs =>
        block.transactions.map(_.parent).exists(txnParentRef => txRefs.exists(_ === txnParentRef))
      }

    if (isChild || hasReferencedAddress) true.pure[F] else hasReferencedTx
  }
}
