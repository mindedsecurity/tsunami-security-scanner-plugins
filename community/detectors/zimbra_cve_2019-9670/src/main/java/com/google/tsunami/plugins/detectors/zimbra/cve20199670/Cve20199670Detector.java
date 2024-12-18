/*
 * Copyright 2024 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.google.tsunami.plugins.detectors.zimbra.cve20199670;

import static com.google.common.base.Preconditions.checkNotNull;
import static com.google.common.collect.ImmutableList.toImmutableList;
import static com.google.tsunami.common.net.http.HttpRequest.post;

import com.google.common.annotations.VisibleForTesting;
import com.google.common.collect.ImmutableList;
import com.google.common.flogger.GoogleLogger;
import com.google.common.util.concurrent.Uninterruptibles;
import com.google.protobuf.ByteString;
import com.google.protobuf.util.Timestamps;
import com.google.tsunami.common.data.NetworkServiceUtils;
import com.google.tsunami.common.net.http.HttpClient;
import com.google.tsunami.common.net.http.HttpRequest;
import com.google.tsunami.common.net.http.HttpHeaders;
import com.google.tsunami.common.net.http.HttpResponse;
import com.google.tsunami.common.time.UtcClock;
import com.google.tsunami.plugin.PluginType;
import com.google.tsunami.plugin.VulnDetector;
import com.google.tsunami.plugin.annotations.PluginInfo;
import com.google.tsunami.plugin.payload.Payload;
import com.google.tsunami.plugin.payload.PayloadGenerator;
import com.google.tsunami.proto.DetectionReport;
import com.google.tsunami.proto.DetectionReportList;
import com.google.tsunami.proto.DetectionStatus;
import com.google.tsunami.proto.NetworkService;
import com.google.tsunami.proto.PayloadGeneratorConfig;
import com.google.tsunami.proto.Severity;
import com.google.tsunami.proto.TargetInfo;
import com.google.tsunami.proto.Vulnerability;
import com.google.tsunami.proto.VulnerabilityId;

import java.util.UUID;
import java.io.IOException;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import javax.inject.Inject;

/** A {@link VulnDetector} that detects highly critical RCE CVE-2019-9670. */
@PluginInfo(
    type = PluginType.VULN_DETECTION,
    name = "CVE-2019-9670 Detector",
    version = "0.1",
    description = "Detects CVE-2019-9670 XXE vulnerability in Zimbra.",
    author = "Leonardo Tamiano (leonardo.tamiano@mindedsecurity.com)",
    bootstrapModule = Cve20199670DetectorBootstrapModule.class)
public final class Cve20199670Detector implements VulnDetector {
  private static final GoogleLogger logger = GoogleLogger.forEnclosingClass();

  @VisibleForTesting static final String VULNERABILITY_REPORT_PUBLISHER = "TSUNAMI_COMMUNITY";
  @VisibleForTesting static final String VULNERABILITY_REPORT_ID = "CVE_2019-9670";

  @VisibleForTesting static final String VULNERABILITY_REPORT_TITLE = "PHP RCE CVE-2019-9670";

  // TODO
  @VisibleForTesting
  static final String VULN_DESCRIPTION = "";

  @VisibleForTesting
  static final String RECOMMENDATION = "";

  private static final String PAYLOAD_REFLECTED_TEMPLATE =
      "<?xml version=\"1.0\" ?>\n"      
         + "<!DOCTYPE foo [<!ELEMENT foo ANY>\n"
         + "<!ENTITY xxe \"%s\"> ]>\n"
         + "<Request>\n"
         + "<EMailAddress>email</EMailAddress>\n"
         + "<AcceptableResponseSchema>&xxe;</AcceptableResponseSchema>\n"
      + "</Request>";

  private static final String AUTODISCOVER_PATH = "Autodiscover/Autodiscover.xml";

  private static final String TEST_STRING = String.format("%s", UUID.randomUUID());

  private final Clock utcClock;
  private final HttpClient httpClient;
  private final PayloadGenerator payloadGenerator;

  @Inject
  Cve20199670Detector(
      @UtcClock Clock utcClock, HttpClient httpClient, PayloadGenerator payloadGenerator) {
    this.utcClock = checkNotNull(utcClock);
    this.httpClient = checkNotNull(httpClient).modify().setFollowRedirects(false).build();
    this.payloadGenerator = checkNotNull(payloadGenerator);
  }

  @Override
  public DetectionReportList detect(
      TargetInfo targetInfo, ImmutableList<NetworkService> matchedServices) {
    logger.atInfo().log("Starting CVE-2019-9670 RCE detection.");

    return DetectionReportList.newBuilder()
        .addAllDetectionReports(
            matchedServices.stream()
                .filter(NetworkServiceUtils::isWebService)
                .filter(this::isServiceVulnerable)
                .map(networkService -> buildDetectionReport(targetInfo, networkService))
                .collect(toImmutableList()))
        .build();
  }

  private boolean isServiceVulnerable(NetworkService networkService) {
      boolean isVulnerable = false;      
      String targetUri =
	  NetworkServiceUtils.buildWebApplicationRootUrl(networkService) + AUTODISCOVER_PATH;

      String reflectedPayload = String.format(PAYLOAD_REFLECTED_TEMPLATE, TEST_STRING);

      HttpRequest request =
	  HttpRequest.post(targetUri)
	  .setHeaders(HttpHeaders.builder().addHeader("Content-Type", "application/xml").build())
	  .setRequestBody(ByteString.copyFromUtf8(reflectedPayload))
	  .build();

      try {
	  HttpResponse response = httpClient.send(request, networkService);	  
	  isVulnerable = (response.status().code() == 503) && response.bodyString().map(body -> body.contains(TEST_STRING)).orElse(false);
      } catch (IOException e) {
	  logger.atWarning().withCause(e).log("Request to target '%s' failed", targetUri);
	  return false;
      }
      
      return isVulnerable;
  }

  // TODO: add test with callback if callback server is available
    
  private DetectionReport buildDetectionReport(
      TargetInfo targetInfo, NetworkService vulnerableNetworkService) {
    return DetectionReport.newBuilder()
        .setTargetInfo(targetInfo)
        .setNetworkService(vulnerableNetworkService)
        .setDetectionTimestamp(Timestamps.fromMillis(Instant.now(utcClock).toEpochMilli()))
        .setDetectionStatus(DetectionStatus.VULNERABILITY_VERIFIED)
        .setVulnerability(
            Vulnerability.newBuilder()
                .setMainId(
                    VulnerabilityId.newBuilder()
                        .setPublisher(VULNERABILITY_REPORT_PUBLISHER)
                        .setValue(VULNERABILITY_REPORT_ID))
                .setSeverity(Severity.CRITICAL)
                .setTitle(VULNERABILITY_REPORT_TITLE)
                .setDescription(VULN_DESCRIPTION)
                .setRecommendation(RECOMMENDATION))
        .build();
  }
}
