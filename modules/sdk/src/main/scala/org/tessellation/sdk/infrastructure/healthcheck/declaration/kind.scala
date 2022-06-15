package org.tessellation.sdk.infrastructure.healthcheck.declaration

import derevo.circe.magnolia.{decoder, encoder}
import derevo.derive

object kind {

  @derive(encoder, decoder)
  sealed trait PeerDeclarationKind

  case object Facility extends PeerDeclarationKind
  case object Proposal extends PeerDeclarationKind
  case object Signature extends PeerDeclarationKind

}
