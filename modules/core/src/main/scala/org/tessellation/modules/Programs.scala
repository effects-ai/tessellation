package org.tessellation.modules

import cats.effect.Async

import org.tessellation.domain.cluster.programs.TrustPush
import org.tessellation.sdk.domain.cluster.programs.{Joining, PeerDiscovery}
import org.tessellation.sdk.modules.SdkPrograms

object Programs {

  def make[F[_]: Async](
    sdkPrograms: SdkPrograms[F],
    storages: Storages[F],
    services: Services[F]
  ): Programs[F] = {
    val trustPush = TrustPush.make(storages.trust, services.gossip)

    new Programs[F](sdkPrograms.peerDiscovery, sdkPrograms.joining, trustPush) {}
  }
}

sealed abstract class Programs[F[_]] private (
  val peerDiscovery: PeerDiscovery[F],
  val joining: Joining[F],
  val trustPush: TrustPush[F]
)
