/*
 * Copyright (c) 2014-2020 Snowplow Analytics Ltd. All rights reserved.
 *
 * This program is licensed to you under the Apache License Version 2.0,
 * and you may not use this file except in compliance with the Apache License Version 2.0.
 * You may obtain a copy of the Apache License Version 2.0 at http://www.apache.org/licenses/LICENSE-2.0.
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the Apache License Version 2.0 is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the Apache License Version 2.0 for the specific language governing permissions and limitations there under.
 */
package com.snowplowanalytics.snowplow.enrich.common.utils

import cats.Monad
import cats.data.{EitherT, NonEmptyList, Validated, ValidatedNel}
import cats.effect.Clock
import cats.implicits._

import io.circe.Json

import com.snowplowanalytics.iglu.client.{Client, ClientError}
import com.snowplowanalytics.iglu.client.resolver.registries.RegistryLookup

import com.snowplowanalytics.iglu.core.circe.instances._
import com.snowplowanalytics.iglu.core.{SchemaCriterion, SchemaKey, SelfDescribingData}

import com.snowplowanalytics.snowplow.badrows.FailureDetails

import com.snowplowanalytics.snowplow.enrich.common.outputs.EnrichedEvent

/** Contain the functions to validate:
 *  - An unstructured event,
 *  - The input contexts of an event,
 *  - The contexts added by the enrichments.
 */
object IgluUtils {

  /** Extract unstructured event from event and validate against its schema
   *  @param event Snowplow event from which to extract unstructured event (in String)
   *  @param client Iglu client used for SDJ validation
   *  @param field Name of the field containing the unstructured event, to put in the bad row
   *               in case of failure
   *  @param criterion Expected schema for the JSON containing the unstructured event
   *  @return Valid unstructured event if the input event has one
   */
  def extractAndValidateUnstructEvent[F[_]: Monad: RegistryLookup: Clock](
    event: EnrichedEvent,
    client: Client[F, Json],
    field: String = "ue_properties",
    criterion: SchemaCriterion = SchemaCriterion("com.snowplowanalytics.snowplow", "unstruct_event",
      "jsonschema", 1, 0)
  ): F[Validated[FailureDetails.SchemaViolation, Option[SelfDescribingData[Json]]]] =
    (Option(event.unstruct_event) match {
      case Some(rawUnstructEvent) =>
        for {
          // Validate input Json string and extract unstructured event
          unstruct <- extractInputData(rawUnstructEvent, field, criterion, client)
          // Parse Json unstructured event as SelfDescribingData[Json]
          unstructSDJ <- SelfDescribingData
            .parse(unstruct)
            .leftMap(FailureDetails.SchemaViolation.NotIglu(unstruct, _))
            .toEitherT[F]
          // Check SelfDescribingData[Json] of unstructured event
          _ <- check(client, unstructSDJ)
            .leftMap {
              case (schemaKey, clientError) =>
                FailureDetails.SchemaViolation.IgluError(schemaKey, clientError)
            }
            .leftWiden[FailureDetails.SchemaViolation]
        } yield unstructSDJ.some
      case None =>
        EitherT.rightT[F, FailureDetails.SchemaViolation](none[SelfDescribingData[Json]])
    }).value
      .map(_.toValidated)

  /** Extract list of custom contexts from event and validate each against its schema
   *  @param event Snowplow enriched event from which to extract custom contexts (in String)
   *  @param client Iglu client used for SDJ validation
   *  @param field Name of the field containing the contexts, to put in the bad row
   *               in case of failure
   *  @param criterion Expected schema for the JSON containing the contexts
   *  @return List will all contexts provided that they are all valid
   */
  def extractAndValidateInputContexts[F[_]: Monad: RegistryLookup: Clock](
    event: EnrichedEvent,
    client: Client[F, Json],
    field: String = "contexts",
    criterion: SchemaCriterion = SchemaCriterion("com.snowplowanalytics.snowplow", "contexts",
      "jsonschema", 1, 0)
  ): F[ValidatedNel[FailureDetails.SchemaViolation, List[SelfDescribingData[Json]]]] =
    (Option(event.contexts) match {
      case Some(rawContexts) =>
        for {
          // Validate input Json string and extract contexts
          contexts <- extractInputData(rawContexts, field, criterion, client)
            .map(_.asArray.get.toList) // .get OK because SDJ wrapping the contexts valid
            .leftMap(NonEmptyList.one)
          // Parse and validate each SDJ and merge the errors
          contextsSDJ <- EitherT(
            contexts
              .map(parseAndValidateSDJ_sv(_, client).toValidatedNel)
              .sequence
              .map(_.sequence.toEither)
          )
        } yield contextsSDJ
      case None =>
        EitherT.rightT[F, NonEmptyList[FailureDetails.SchemaViolation]](
          List.empty[SelfDescribingData[Json]]
        )
    }).value
      .map(_.toValidated)

  /** Validate each context added by the enrichments against its schema
   *  @param client Iglu client used for SDJ validation
   *  @param sdjs List of enrichments contexts to be added to the enriched event
   *  @return Unit if all the contexts are valid
   */
  def validateEnrichmentsContexts[F[_]: Monad: RegistryLookup: Clock](
    client: Client[F, Json],
    sdjs: List[SelfDescribingData[Json]]
  ): F[ValidatedNel[FailureDetails.EnrichmentFailure, Unit]] =
    checkList(client, sdjs)
      .leftMap(
        _.map {
          case (schemaKey, clientError) =>
            val enrichmentInfo =
              FailureDetails.EnrichmentInformation(schemaKey, "enrichments-contexts-validation")
            FailureDetails.EnrichmentFailure(
              enrichmentInfo.some,
              FailureDetails.EnrichmentFailureMessage.IgluError(schemaKey, clientError)
            )
        }
      )
      .value
      .map(_.toValidated)

  // Used to extract .data for input custom contexts and input unstructured event
  private def extractInputData[F[_]: Monad: RegistryLookup: Clock](
    rawJson: String,
    field: String, // to put in the bad row
    expectedCriterion: SchemaCriterion,
    client: Client[F, Json]
  ): EitherT[F, FailureDetails.SchemaViolation, Json] =
    for {
      // Parse Json string with the SDJ
      json <- JsonUtils
        .extractJson(rawJson)
        .leftMap(e => FailureDetails.SchemaViolation.NotJson(field, rawJson.some, e))
        .toEitherT[F]
      // Parse Json as SelfDescribingData[Json] (which contains the .data that we want)
      sdj <- SelfDescribingData
        .parse(json)
        .leftMap(FailureDetails.SchemaViolation.NotIglu(json, _))
        .toEitherT[F]
      // Check that the schema of SelfDescribingData[Json] is the expected one
      _ <- if (validateCriterion(sdj, expectedCriterion))
        EitherT.rightT[F, FailureDetails.SchemaViolation](sdj)
      else
        EitherT
          .leftT[F, SelfDescribingData[Json]](
            FailureDetails.SchemaViolation.CriterionMismatch(sdj.schema, expectedCriterion)
          )
      // Check that the SDJ holding the .data is valid
      _ <- check(client, sdj)
        .leftMap {
          case (schemaKey, clientError) =>
            FailureDetails.SchemaViolation.IgluError(schemaKey, clientError)
        }
      // Extract .data of SelfDescribingData[Json]
      data <- EitherT.rightT[F, FailureDetails.SchemaViolation](sdj.data)
    } yield data

  // Check that the schema of a SDJ matches the expected one
  private def validateCriterion(
    sdj: SelfDescribingData[Json],
    criterion: SchemaCriterion
  ): Boolean =
    criterion.matches(sdj.schema)

  // Check that a SDJ is valid
  private def check[F[_]: Monad: RegistryLookup: Clock](
    client: Client[F, Json],
    sdj: SelfDescribingData[Json]
  ): EitherT[F, (SchemaKey, ClientError), Unit] =
    client
      .check(sdj)
      .leftMap(clientErr => (sdj.schema, clientErr))

  // Check a list of SDJs and merge the Iglu errors
  private def checkList[F[_]: Monad: RegistryLookup: Clock](
    client: Client[F, Json],
    sdjs: List[SelfDescribingData[Json]]
  ): EitherT[F, NonEmptyList[(SchemaKey, ClientError)], Unit] = EitherT {
    sdjs
      .map(check(client, _).toValidatedNel)
      .sequence
      .map(_.sequence_.toEither)
  }

  // Parse a Json as a SDJ and check that it's valid
  private def parseAndValidateSDJ_sv[F[_]: Monad: RegistryLookup: Clock]( // _sv for SchemaViolation
    json: Json,
    client: Client[F, Json]
  ): EitherT[F, FailureDetails.SchemaViolation, SelfDescribingData[Json]] =
    for {
      sdj <- SelfDescribingData
        .parse(json)
        .leftMap(FailureDetails.SchemaViolation.NotIglu(json, _))
        .toEitherT[F]
      _ <- check(client, sdj)
        .leftMap {
          case (schemaKey, clientError) =>
            FailureDetails.SchemaViolation
              .IgluError(schemaKey, clientError): FailureDetails.SchemaViolation

        }
    } yield sdj
}
