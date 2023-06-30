package org.tessellation.config

import cats.syntax.partialOrder._

import scala.collection.immutable.SortedMap
import scala.concurrent.duration.FiniteDuration

import org.tessellation.config.types.RewardsConfig._
import org.tessellation.schema.address.Address
import org.tessellation.schema.balance.Amount
import org.tessellation.schema.epoch.EpochProgress
import org.tessellation.sdk.config.AppEnvironment
import org.tessellation.sdk.config.types._

import ciris.Secret
import eu.timepit.refined.auto._
import eu.timepit.refined.types.numeric._
import eu.timepit.refined.types.string.NonEmptyString
import io.estatico.newtype.macros.newtype

object types {
  case class AppConfig(
    environment: AppEnvironment,
    http: HttpConfig,
    db: DBConfig,
    gossip: GossipConfig,
    trust: TrustConfig,
    healthCheck: HealthCheckConfig,
    snapshot: SnapshotConfig,
    collateral: CollateralConfig,
    rewards: RewardsConfig,
    stateChannelOrdinalDelay: Option[PosLong]
  )

  case class DBConfig(
    driver: NonEmptyString,
    url: NonEmptyString,
    user: NonEmptyString,
    password: Secret[String]
  )

  case class TrustDaemonConfig(
    interval: FiniteDuration
  )

  case class TrustConfig(
    daemon: TrustDaemonConfig
  )

  @newtype
  case class Weight(value: NonNegLong)

  case class ProgramsDistributionConfig(
    weights: Map[Address, Weight],
    remainingWeight: Weight
  )

  case class RewardsConfig(
    programs: EpochProgress => ProgramsDistributionConfig = mainnetProgramsDistributionConfig,
    rewardsPerEpoch: SortedMap[EpochProgress, Amount] = mainnetRewardsPerEpoch
  )

  object RewardsConfig {
    val stardustPrimary: Address = Address("DAGSTARDUSTCOLLECTIVEHZOIPHXZUBFGNXWJETZVSPAPAHMLXS")
    val stardustSecondary: Address = Address("DAG8VT7bxjs1XXBAzJGYJDaeyNxuThikHeUTp9XY")
    val softStaking: Address = Address("DAG77VVVRvdZiYxZ2hCtkHz68h85ApT5b2xzdTkn")
    val testnet: Address = Address("DAG0qE5tkz6cMUD5M2dkqgfV4TQCzUUdAP5MFM9P")
    val dataPool: Address = Address("DAG3RXBWBJq1Bf38rawASakLHKYMbRhsDckaGvGu")

    val mainnetProgramsDistributionConfig: EpochProgress => ProgramsDistributionConfig = {
      case epoch if epoch < EpochProgress(1336392L) =>
        ProgramsDistributionConfig(
          weights = Map(
            stardustPrimary -> Weight(5L),
            stardustSecondary -> Weight(5L),
            softStaking -> Weight(20L),
            testnet -> Weight(1L),
            dataPool -> Weight(65L)
          ),
          remainingWeight = Weight(4L) // facilitators
        )
      case _ =>
        ProgramsDistributionConfig(
          weights = Map(
            stardustPrimary -> Weight(5L),
            stardustSecondary -> Weight(5L),
            testnet -> Weight(5L),
            dataPool -> Weight(55L)
          ),
          remainingWeight = Weight(30L) // facilitators
        )
    }

    val mainnetRewardsPerEpoch: SortedMap[EpochProgress, Amount] = SortedMap(
      EpochProgress(1296000L) -> Amount(658_43621389L),
      EpochProgress(2592000L) -> Amount(329_21810694L),
      EpochProgress(3888000L) -> Amount(164_60905347L),
      EpochProgress(5184000L) -> Amount(82_30452674L)
    )
  }
}
