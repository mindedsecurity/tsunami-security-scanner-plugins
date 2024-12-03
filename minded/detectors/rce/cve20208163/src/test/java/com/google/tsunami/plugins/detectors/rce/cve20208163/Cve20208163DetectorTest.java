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
package com.google.tsunami.plugins.detectors.rce.cve20208163;

import static com.google.common.truth.extensions.proto.ProtoTruth.assertThat;
import static com.google.tsunami.common.data.NetworkEndpointUtils.forHostnameAndPort;

import com.google.common.collect.ImmutableList;
import com.google.inject.Guice;
import com.google.protobuf.util.Timestamps;
import com.google.tsunami.common.time.testing.FakeUtcClock;
import com.google.tsunami.common.time.testing.FakeUtcClockModule;
import com.google.tsunami.proto.AdditionalDetail;
import com.google.tsunami.proto.DetectionReport;
import com.google.tsunami.proto.DetectionReportList;
import com.google.tsunami.proto.DetectionStatus;
import com.google.tsunami.proto.NetworkService;
import com.google.tsunami.proto.TransportProtocol;
import com.google.tsunami.proto.Severity;
import com.google.tsunami.proto.Software;
import com.google.tsunami.proto.TargetInfo;
import com.google.tsunami.proto.TextData;
import com.google.tsunami.proto.Vulnerability;
import com.google.tsunami.proto.VulnerabilityId;
import java.time.Instant;
import javax.inject.Inject;
import org.junit.Before;
import org.junit.After;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;
import okhttp3.mockwebserver.MockWebServer;
import java.io.IOException;

/** Unit tests for {@link Cve20208163Detector}. */
@RunWith(JUnit4.class)
public final class Cve20208163DetectorTest {
  private final FakeUtcClock fakeUtcClock =
      FakeUtcClock.create().setNow(Instant.parse("2020-01-01T00:00:00.00Z"));

  @Inject private Cve20208163Detector detector;

  private MockWebServer mockWebService;

  @Before
  public void setUp() throws IOException {

    mockWebService = new MockWebServer();
    mockWebService.start();      
      
    Guice.createInjector(
            new FakeUtcClockModule(fakeUtcClock), new Cve20208163DetectorBootstrapModule())
        .injectMembers(this);
  }

  @After
  public void tearDown() throws Exception {
    mockWebService.shutdown();
  }  

  // In Tsunami, unit test names should follow the following general convention:
  // functionUnderTest_condition_outcome.
  //
  // TODO: implement proper tests
  //
  @Test
  public void detect_whenVulnerable_reportsVulnerability() {
    NetworkService service = NetworkService.newBuilder()
      .setNetworkEndpoint(forHostnameAndPort(mockWebService.getHostName(), mockWebService.getPort()))
      .setTransportProtocol(TransportProtocol.TCP)
      .setSoftware(Software.newBuilder().setName("TODO"))
      .setServiceName("http")
      .build();
    
    DetectionReportList detectionReports =
        detector.detect(TargetInfo.getDefaultInstance(), ImmutableList.of(service));
    
    assertThat(detectionReports.getDetectionReportsList())
        .containsExactly(
            DetectionReport.newBuilder()
                .setTargetInfo(TargetInfo.getDefaultInstance())
                .setNetworkService(service)
                .setDetectionTimestamp(
                    Timestamps.fromMillis(Instant.now(fakeUtcClock).toEpochMilli()))
                .setDetectionStatus(DetectionStatus.VULNERABILITY_VERIFIED)
                .setVulnerability(
                    Vulnerability.newBuilder()
                        .setMainId(
                            VulnerabilityId.newBuilder()
                                .setPublisher("TODO")
                                .setValue("CVE_2020_8163"))
                        .setSeverity(Severity.CRITICAL)
                        .setTitle("CVE-2020-8163")
		        .setDescription("TODO"))
	    .build());
  }
    
}


