package org.tessellation.dag.transaction

import cats.data.ValidatedNec
import cats.effect.Async
import cats.syntax.all._

import org.tessellation.dag.transaction.TransactionValidator.TransactionValidationErrorOr
import org.tessellation.ext.cats.syntax.validated._
import org.tessellation.schema.address.Address
import org.tessellation.schema.transaction.DAGTransaction
import org.tessellation.security.signature.SignedValidator.SignedValidationError
import org.tessellation.security.signature.{Signed, SignedValidator}

import derevo.cats.{eqv, show}
import derevo.derive
import eu.timepit.refined.auto._

trait TransactionValidator[F[_]] {

  def validate(signedTransaction: Signed[DAGTransaction]): F[TransactionValidationErrorOr[Signed[DAGTransaction]]]

}

object TransactionValidator {

  def make[F[_]: Async](
    signedValidator: SignedValidator[F]
  ): TransactionValidator[F] =
    new TransactionValidator[F] {

      def validate(
        signedTransaction: Signed[DAGTransaction]
      ): F[TransactionValidationErrorOr[Signed[DAGTransaction]]] =
        for {
          signaturesV <- signedValidator
            .validateSignatures(signedTransaction)
            .map(_.errorMap[TransactionValidationError](InvalidSigned))
          srcAddressSignatureV <- validateSourceAddressSignature(signedTransaction)
          differentSrcAndDstV = validateDifferentSourceAndDestinationAddress(signedTransaction)
        } yield
          signaturesV
            .productR(srcAddressSignatureV)
            .productR(differentSrcAndDstV)

      private def validateSourceAddressSignature(
        signedTx: Signed[DAGTransaction]
      ): F[TransactionValidationErrorOr[Signed[DAGTransaction]]] =
        signedValidator
          .isSignedExclusivelyBy(signedTx, signedTx.source)
          .map(_.errorMap[TransactionValidationError](_ => NotSignedBySourceAddressOwner))

      private def validateDifferentSourceAndDestinationAddress(
        signedTx: Signed[DAGTransaction]
      ): TransactionValidationErrorOr[Signed[DAGTransaction]] =
        if (signedTx.source =!= signedTx.destination)
          signedTx.validNec[TransactionValidationError]
        else
          SameSourceAndDestinationAddress(signedTx.source).invalidNec[Signed[DAGTransaction]]
    }

  @derive(eqv, show)
  sealed trait TransactionValidationError
  case class InvalidSigned(error: SignedValidationError) extends TransactionValidationError
  case object NotSignedBySourceAddressOwner extends TransactionValidationError
  case class SameSourceAndDestinationAddress(address: Address) extends TransactionValidationError

  type TransactionValidationErrorOr[A] = ValidatedNec[TransactionValidationError, A]
}
