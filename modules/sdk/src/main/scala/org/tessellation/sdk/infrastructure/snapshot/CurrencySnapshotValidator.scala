package org.tessellation.sdk.infrastructure.snapshot

import cats.data.ValidatedNec
import cats.effect.kernel.Async
import cats.syntax.all._

import org.tessellation.currency.dataApplication.BaseDataApplicationService
import org.tessellation.currency.dataApplication.dataApplication.DataApplicationBlock
import org.tessellation.currency.schema.currency._
import org.tessellation.ext.cats.syntax.validated.validatedSyntax
import org.tessellation.kryo.KryoSerializer
import org.tessellation.schema.Block
import org.tessellation.sdk.domain.rewards.Rewards
import org.tessellation.sdk.infrastructure.consensus.trigger.{ConsensusTrigger, EventTrigger, TimeTrigger}
import org.tessellation.sdk.snapshot.currency.{CurrencySnapshotArtifact, CurrencySnapshotEvent}
import org.tessellation.security.signature.SignedValidator.SignedValidationError
import org.tessellation.security.signature.{Signed, SignedValidator}

import derevo.cats.{eqv, show}
import derevo.derive
import eu.timepit.refined.auto._
import monocle.syntax.all._

trait CurrencySnapshotValidator[F[_]] {

  type CurrencySnapshotValidationErrorOr[A] = ValidatedNec[CurrencySnapshotValidationError, A]

  def validateSignedSnapshot(
    lastArtifact: Signed[CurrencySnapshotArtifact],
    lastContext: CurrencySnapshotContext,
    artifact: Signed[CurrencySnapshotArtifact]
  ): F[CurrencySnapshotValidationErrorOr[(Signed[CurrencyIncrementalSnapshot], CurrencySnapshotContext)]]

  def validateSnapshot(
    lastArtifact: Signed[CurrencySnapshotArtifact],
    lastContext: CurrencySnapshotContext,
    artifact: CurrencySnapshotArtifact
  ): F[CurrencySnapshotValidationErrorOr[(CurrencyIncrementalSnapshot, CurrencySnapshotContext)]]
}

object CurrencySnapshotValidator {

  def make[F[_]: Async: KryoSerializer](
    currencySnapshotCreator: CurrencySnapshotCreator[F],
    signedValidator: SignedValidator[F],
    rewards: Option[Rewards[F, CurrencySnapshotStateProof, CurrencyIncrementalSnapshot]],
    dataApplication: Option[BaseDataApplicationService[F]]
  ): CurrencySnapshotValidator[F] = new CurrencySnapshotValidator[F] {

    def validateSignedSnapshot(
      lastArtifact: Signed[CurrencySnapshotArtifact],
      lastContext: CurrencySnapshotContext,
      artifact: Signed[CurrencySnapshotArtifact]
    ): F[CurrencySnapshotValidationErrorOr[(Signed[CurrencyIncrementalSnapshot], CurrencySnapshotContext)]] =
      validateSigned(artifact).flatMap { signedV =>
        validateSnapshot(lastArtifact, lastContext, artifact).map { snapshotV =>
          signedV.product(snapshotV.map { case (_, info) => info })
        }
      }

    def validateSnapshot(
      lastArtifact: Signed[CurrencySnapshotArtifact],
      lastContext: CurrencySnapshotContext,
      artifact: CurrencySnapshotArtifact
    ): F[CurrencySnapshotValidationErrorOr[(CurrencyIncrementalSnapshot, CurrencySnapshotContext)]] = for {
      contentV <- validateRecreateContent(lastArtifact, lastContext, artifact)
      blocksV <- contentV.map(validateNotAcceptedBlocks).pure[F]
    } yield
      (contentV, blocksV).mapN {
        case (creationResult, _) => (creationResult.artifact, creationResult.context)
      }

    def validateSigned(
      signedSnapshot: Signed[CurrencyIncrementalSnapshot]
    ): F[CurrencySnapshotValidationErrorOr[Signed[CurrencyIncrementalSnapshot]]] =
      signedValidator.validateSignatures(signedSnapshot).map(_.errorMap(InvalidSigned))

    def validateRecreateContent(
      lastArtifact: Signed[CurrencySnapshotArtifact],
      lastContext: CurrencySnapshotContext,
      expected: CurrencySnapshotArtifact
    ): F[CurrencySnapshotValidationErrorOr[CurrencySnapshotCreationResult]] = {
      val events: Set[CurrencySnapshotEvent] = expected.blocks.unsorted.map(_.block.asLeft[Signed[DataApplicationBlock]])

      val recreateFn = (trigger: ConsensusTrigger) =>
        currencySnapshotCreator
          .createProposalArtifact(lastArtifact.ordinal, lastArtifact, lastContext, trigger, events, rewards)
          // Rewrite if implementation not provided
          .map { creationResult =>
            rewards match {
              case Some(_) => creationResult
              case None    => creationResult.focus(_.artifact.rewards).replace(expected.rewards)
            }
          }
          // Rewrite if implementation not provided
          .map { creationResult =>
            dataApplication match {
              case Some(_) => creationResult
              case None    => creationResult.focus(_.artifact.data).replace(expected.data)
            }
          }
          .map { creationResult =>
            if (creationResult.artifact =!= expected)
              SnapshotDifferentThanExpected(expected, creationResult.artifact).invalidNec
            else
              creationResult.validNec
          }

      recreateFn(TimeTrigger).flatMap { tV =>
        recreateFn(EventTrigger).map(_.orElse(tV))
      }
    }

    def validateNotAcceptedBlocks(
      creationResult: CurrencySnapshotCreationResult
    ): CurrencySnapshotValidationErrorOr[Unit] =
      if (creationResult.awaitingBlocks.nonEmpty || creationResult.rejectedBlocks.nonEmpty)
        SomeBlocksWereNotAccepted(creationResult.awaitingBlocks, creationResult.rejectedBlocks).invalidNec
      else ().validNec
  }

}

@derive(eqv, show)
sealed trait CurrencySnapshotValidationError

case class SnapshotDifferentThanExpected(expected: CurrencyIncrementalSnapshot, actual: CurrencyIncrementalSnapshot)
    extends CurrencySnapshotValidationError

case class SomeBlocksWereNotAccepted(awaitingBlocks: Set[Signed[Block]], rejectedBlocks: Set[Signed[Block]])
    extends CurrencySnapshotValidationError

case class InvalidSigned(error: SignedValidationError) extends CurrencySnapshotValidationError
