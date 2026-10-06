/*
 * Copyright © 2026 Callibrity, Inc. (contactus@callibrity.com)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.callibrity.cryptoagility.demo;

import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.nio.file.Files;
import java.nio.file.Path;
import org.junit.jupiter.api.DisplayNameGeneration;
import org.junit.jupiter.api.DisplayNameGenerator;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

@DisplayNameGeneration(DisplayNameGenerator.ReplaceUnderscores.class)
class DemoTest {

  @TempDir Path dataDir;

  @Nested
  class Given_a_single_command {

    @Test
    void runs_it_against_the_data_directory_it_is_given() throws IOException {
      var output = new StringWriter();

      Demo.run(
          new String[] {"write", "customer", "record", "#1"}, dataDir, new PrintWriter(output));

      assertTrue(output.toString().contains("saved record-0001"));
      assertTrue(Files.isRegularFile(dataDir.resolve("envelopes").resolve("record-0001.envelope")));
    }

    @Test
    void a_later_run_reads_what_an_earlier_one_wrote() throws IOException {
      Demo.run(new String[] {"write", "hello"}, dataDir, new PrintWriter(new StringWriter()));
      var output = new StringWriter();

      Demo.run(new String[] {"read"}, dataDir, new PrintWriter(output));

      assertTrue(output.toString().contains("-> hello"));
    }
  }
}
