package org.tessellation.sdk.infrastructure.consensus

import java.security.KeyPair

import cats.effect.Async
import cats.effect.std.{Random, Supervisor}
import cats.kernel.Next
import cats.syntax.flatMap._
import cats.syntax.functor._
import cats.{Eq, Order, Show}

import scala.reflect.runtime.universe.TypeTag

import org.tessellation.kryo.KryoSerializer
import org.tessellation.schema.peer.PeerId
import org.tessellation.sdk.config.types.ConsensusConfig
import org.tessellation.sdk.domain.cluster.services.Session
import org.tessellation.sdk.domain.cluster.storage.ClusterStorage
import org.tessellation.sdk.domain.consensus.ConsensusFunctions
import org.tessellation.sdk.domain.gossip.Gossip
import org.tessellation.sdk.domain.node.NodeStorage
import org.tessellation.sdk.infrastructure.gossip.RumorHandler
import org.tessellation.sdk.infrastructure.metrics.Metrics
import org.tessellation.security.SecurityProvider

import io.circe.{Decoder, Encoder}
import org.http4s.client.Client

object Consensus {

  def make[
    F[_]: Async: Supervisor: Random: KryoSerializer: SecurityProvider: Metrics,
    Event: TypeTag: Decoder,
    Key: Show: Order: Next: TypeTag: Encoder: Decoder,
    Artifact <: AnyRef: Show: Eq: TypeTag: Encoder: Decoder
  ](
    consensusFns: ConsensusFunctions[F, Event, Key, Artifact],
    gossip: Gossip[F],
    selfId: PeerId,
    keyPair: KeyPair,
    consensusConfig: ConsensusConfig,
    seedlist: Option[Set[PeerId]],
    clusterStorage: ClusterStorage[F],
    nodeStorage: NodeStorage[F],
    client: Client[F],
    session: Session[F]
  ): F[Consensus[F, Event, Key, Artifact]] =
    for {
      storage <- ConsensusStorage.make[F, Event, Key, Artifact]
      stateUpdater = ConsensusStateUpdater.make[F, Event, Key, Artifact](
        consensusFns,
        storage,
        gossip,
        keyPair
      )
      stateCreator = ConsensusStateCreator.make[F, Event, Key, Artifact](
        consensusFns,
        storage,
        gossip,
        selfId,
        seedlist
      )
      stateRemover = ConsensusStateRemover.make[F, Event, Key, Artifact](
        storage,
        gossip
      )
      consClient = ConsensusClient.make[F, Key, Artifact](client, session)
      manager <- ConsensusManager.make[F, Event, Key, Artifact](
        consensusConfig,
        storage,
        stateCreator,
        stateUpdater,
        stateRemover,
        nodeStorage,
        clusterStorage,
        consClient,
        selfId
      )
      handler = ConsensusHandler.make[F, Event, Key, Artifact](storage, manager, consensusFns)
      routes = new ConsensusRoutes[F, Key, Artifact](storage)
    } yield new Consensus(handler, storage, manager, routes)
}

sealed class Consensus[F[_]: Async, Event, Key, Artifact] private (
  val handler: RumorHandler[F],
  val storage: ConsensusStorage[F, Event, Key, Artifact],
  val manager: ConsensusManager[F, Key, Artifact],
  val routes: ConsensusRoutes[F, Key, Artifact]
) {}
