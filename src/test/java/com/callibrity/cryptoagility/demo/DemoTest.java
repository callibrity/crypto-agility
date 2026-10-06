package com.callibrity.cryptoagility.demo;

import org.junit.jupiter.api.DisplayNameGeneration;
import org.junit.jupiter.api.DisplayNameGenerator;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.nio.file.Files;
import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.assertTrue;

@DisplayNameGeneration(DisplayNameGenerator.ReplaceUnderscores.class)
class DemoTest {

    @TempDir
    Path dataDir;

    @Nested
    class Given_a_single_command {

        @Test
        void runs_it_against_the_data_directory_it_is_given() throws IOException {
            var output = new StringWriter();

            Demo.run(new String[] {"write", "customer", "record", "#1"}, dataDir, new PrintWriter(output));

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
