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

import static java.nio.charset.StandardCharsets.UTF_8;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.callibrity.cryptoagility.command.StoreCommands;
import com.callibrity.cryptoagility.command.Workspace;
import com.callibrity.cryptoagility.envelope.Envelope;
import com.callibrity.cryptoagility.kms.KeyMetadata;
import com.callibrity.cryptoagility.kms.KeyTypes;
import com.callibrity.cryptoagility.kms.LocalKms;
import com.callibrity.cryptoagility.store.EnvelopeStore.Stored;
import com.callibrity.cryptoagility.wrapper.AesGcmWrapper;
import com.callibrity.cryptoagility.wrapper.KeyWrapper;
import com.callibrity.cryptoagility.wrapper.WrappedDek;
import java.io.IOException;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.util.List;
import javax.crypto.SecretKey;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayNameGeneration;
import org.junit.jupiter.api.DisplayNameGenerator;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

@DisplayNameGeneration(DisplayNameGenerator.ReplaceUnderscores.class)
class ShellTest {

  @TempDir Path dataDir;

  private Workspace ws;
  private Shell shell;

  private StringWriter output;

  @BeforeEach
  void open_a_fresh_session() {
    ws = new Workspace(dataDir);
    output = new StringWriter();
    shell = new Shell(ws, new PrintWriter(output));
  }

  private List<String> storedAlgorithms() throws IOException {
    return ws.envelopes().all().stream().map(stored -> stored.envelope().alg()).toList();
  }

  private String plaintextOf(int index) throws IOException, GeneralSecurityException {
    Envelope env = ws.envelopes().all().get(index).envelope();
    return new String(env.open(ws.kms()), UTF_8);
  }

  @Nested
  class When_a_session_starts {

    @Test
    void new_data_is_wrapped_with_rsa() {
      assertEquals("RSA-OAEP-3072", shell.current());
    }

    @Test
    void generates_no_keys_until_one_is_needed() throws IOException {
      shell.execute("list");

      assertTrue(ws.kms().listKeys().isEmpty());
    }
  }

  @Nested
  class When_the_algorithm_is_changed_with_use {

    @Test
    void later_writes_follow_it_and_earlier_records_keep_theirs() throws IOException {
      shell.execute("write customer record #1");
      shell.execute("use ML-KEM-768");
      shell.execute("write customer record #2");

      assertEquals(List.of("RSA-OAEP-3072", "ML-KEM-768"), storedAlgorithms());
    }

    @Test
    void an_unknown_algorithm_is_refused_and_the_current_one_kept() {
      shell.execute("use SIKE-p434");

      assertEquals("RSA-OAEP-3072", shell.current());
    }

    @Test
    void use_on_its_own_changes_nothing() {
      shell.execute("use ML-KEM-768");
      shell.execute("use");

      assertEquals("ML-KEM-768", shell.current());
    }

    @Test
    void rewrap_moves_everything_to_it() throws IOException {
      shell.execute("write customer record #1");
      shell.execute("write customer record #2");
      shell.execute("use ML-KEM-768");

      shell.execute("rewrap");

      assertEquals(List.of("ML-KEM-768", "ML-KEM-768"), storedAlgorithms());
    }
  }

  @Nested
  class When_choosing_a_data_cipher {

    @Test
    void later_writes_use_it_and_the_prompt_says_so() throws IOException {
      shell.execute("use ChaCha20-Poly1305");
      shell.execute("write customer record #1");

      assertEquals("ChaCha20-Poly1305", ws.envelopes().all().getFirst().envelope().enc());
      assertEquals("RSA-OAEP-3072 + ChaCha20-Poly1305", shell.promptLabel());
    }

    @Test
    void the_default_is_not_mentioned_in_the_prompt() {
      assertEquals("RSA-OAEP-3072", shell.promptLabel());
    }
  }

  @Nested
  class When_writing {

    @Test
    void stores_the_text_exactly_as_typed() throws IOException, GeneralSecurityException {
      shell.execute("write   it's 100% fine, \"really\"!  ");

      assertEquals("it's 100% fine, \"really\"!", plaintextOf(0));
    }

    @Test
    void drops_quotes_that_surround_the_whole_text() throws IOException, GeneralSecurityException {
      shell.execute("write \"customer record #1\"");

      assertEquals("customer record #1", plaintextOf(0));
    }

    @Test
    void drops_single_quotes_that_surround_the_whole_text()
        throws IOException, GeneralSecurityException {
      shell.execute("write 'customer record #1'");

      assertEquals("customer record #1", plaintextOf(0));
    }

    @Test
    void keeps_quotes_that_do_not_surround_the_whole_text()
        throws IOException, GeneralSecurityException {
      shell.execute("write \"customer record #1'");

      assertEquals("\"customer record #1'", plaintextOf(0));
    }

    @Test
    void keeps_a_lone_quote_mark() throws IOException, GeneralSecurityException {
      shell.execute("write \"");

      assertEquals("\"", plaintextOf(0));
    }

    @Test
    void stores_nothing_when_no_text_is_given() throws IOException {
      shell.execute("write");

      assertTrue(ws.envelopes().all().isEmpty());
    }
  }

  @Nested
  class When_completing_what_is_typed {

    @Test
    void offers_every_registered_algorithm() {
      assertTrue(shell.algorithms().containsAll(ws.kms().algorithms()));
      assertTrue(shell.algorithms().contains("ChaCha20-Poly1305"));
    }

    @Test
    void offers_every_parameter_set_of_ml_kem_and_hqc() {
      assertTrue(
          shell
              .algorithms()
              .containsAll(
                  List.of(
                      "ML-KEM-512", "ML-KEM-768", "ML-KEM-1024", "HQC-128", "HQC-192", "HQC-256")));
    }

    @Test
    void offers_only_wrap_algorithms_to_retire_and_enable() {
      assertEquals(ws.kms().algorithms(), shell.wrapAlgorithms());
      assertFalse(shell.wrapAlgorithms().contains("ChaCha20-Poly1305"));
    }

    @Test
    void offers_the_ids_of_stored_records() {
      shell.execute("write customer record #1");

      assertEquals(List.of("record-0001"), shell.recordIds());
    }
  }

  @Nested
  class When_listing_keys {

    @Test
    void describes_key_pairs_and_secret_keys_alike() {
      shell.execute("use AES-256-GCMKW");

      assertTrue(shell.execute("keys"));
    }
  }

  @Nested
  class When_a_stored_envelope_is_damaged {

    private void damage(String id, String find, String replace) throws IOException {
      Path file = dataDir.resolve("envelopes").resolve(id + ".envelope");
      Files.writeString(file, Files.readString(file).replaceFirst(find, replace));
    }

    @BeforeEach
    void write_two_records() {
      shell.execute("write customer record #1");
      shell.execute("write customer record #2");
    }

    @Test
    void a_file_that_no_longer_parses_is_reported_and_the_rest_still_read() throws IOException {
      damage("record-0001", "ciphertext=", "ciphertext=!!!");

      shell.execute("read");

      assertTrue(output.toString().contains("record-0001 (damaged) -> UNREADABLE"));
      assertTrue(output.toString().contains("record-0002 (RSA-OAEP-3072) -> customer record #2"));
    }

    @Test
    void every_command_that_reads_the_store_keeps_working() throws IOException {
      damage("record-0001", "ciphertext=", "ciphertext=!!!");

      for (String command : List.of("list", "show", "keys", "cbom", "rewrap", "algorithms")) {
        shell.execute(command);
      }

      assertFalse(output.toString().contains("error:"), output.toString());
      assertTrue(output.toString().contains("damaged"));
    }

    @Test
    void retire_names_only_the_readable_records_it_strands() throws IOException {
      damage("record-0001", "ciphertext=", "ciphertext=!!!");
      shell.execute("use ML-KEM-768");

      shell.execute("retire RSA-OAEP-3072");

      assertTrue(output.toString().contains("1 record(s) still depend on them"), output.toString());
      assertTrue(output.toString().contains("unreadable: record-0002"));
    }

    @Test
    void an_envelope_whose_algorithm_was_removed_cannot_be_opened() throws IOException {
      damage("record-0001", "alg=RSA-OAEP-3072\n", "");

      shell.execute("read");

      assertTrue(output.toString().contains("record-0001 ((none))"));
      assertTrue(output.toString().contains("UNREADABLE"));
      assertFalse(output.toString().contains("customer record #1"));
    }

    @Test
    void an_envelope_that_names_no_key_cannot_be_opened() throws IOException {
      damage("record-0001", "kid=[^\n]*\n", "");

      shell.execute("read");

      assertTrue(output.toString().contains("UNREADABLE: the envelope names no key"));
    }
  }

  @Nested
  class When_there_is_nothing_yet {

    @Test
    void read_show_keys_and_cbom_say_so() {
      for (String command : List.of("read", "show", "keys", "cbom")) {
        shell.execute(command);
      }

      assertTrue(output.toString().contains("nothing stored yet"));
      assertTrue(output.toString().contains("no keys yet"));
    }
  }

  @Nested
  class When_every_record_is_quantum_safe {

    @Test
    void cbom_says_so() {
      shell.execute("use ML-KEM-768");
      shell.execute("write customer record #1");

      shell.execute("cbom");

      assertTrue(
          output.toString().contains("every record is wrapped with a quantum-safe algorithm"));
    }
  }

  @Nested
  class Edge_cases_of_the_commands {

    @Test
    void retire_and_enable_refuse_an_unknown_algorithm() {
      shell.execute("retire SIKE-p434");
      shell.execute("enable SIKE-p434");

      assertEquals(2, output.toString().split("the KMS has no algorithm SIKE-p434", -1).length - 1);
    }

    @Test
    void rewrap_skips_a_record_whose_key_is_disabled() {
      shell.execute("write customer record #1");
      shell.execute("use ML-KEM-768");
      shell.execute("retire RSA-OAEP-3072");

      shell.execute("rewrap");

      assertTrue(output.toString().contains("record-0001 SKIPPED, still RSA-OAEP-3072"));
      assertTrue(output.toString().contains("1 record(s) could not be re-wrapped"));
    }

    @Test
    void keys_shows_a_disabled_key_as_disabled() {
      shell.execute("write customer record #1");
      shell.execute("use ML-KEM-768");
      shell.execute("retire RSA-OAEP-3072");

      shell.execute("keys");

      assertTrue(output.toString().contains("disabled"));
    }

    @Test
    void show_accepts_a_record_by_its_full_id() {
      shell.execute("write customer record #1");

      shell.execute("show record-0001");

      assertTrue(output.toString().contains("╭─ envelope"));
    }

    @Test
    void a_record_with_an_unknown_data_cipher_is_listed_as_unknown_in_the_inventory()
        throws IOException {
      shell.execute("write customer record #1");
      Path file = dataDir.resolve("envelopes").resolve("record-0001.envelope");
      Files.writeString(file, Files.readString(file).replace("enc=AES-256-GCM", "enc=ROT13"));

      shell.execute("cbom");
      shell.execute("algorithms");

      assertTrue(output.toString().contains("ROT13"));
    }
  }

  @Nested
  class Output {

    @Test
    void goes_to_the_shell_writer_rather_than_standard_output() {
      shell.execute("write customer record #1");

      assertTrue(output.toString().contains("saved record-0001"));
    }

    @Test
    void includes_errors() {
      shell.execute("frobnicate");

      assertTrue(output.toString().contains("unknown command frobnicate"));
    }
  }

  @Nested
  class When_an_algorithm_is_retired {

    @Test
    void records_still_wrapped_with_it_can_no_longer_be_read() {
      shell.execute("write customer record #1");
      shell.execute("use ML-KEM-768");

      shell.execute("retire RSA-OAEP-3072");
      shell.execute("read");

      assertTrue(output.toString().contains("1 record(s) still depend on them"));
      assertTrue(output.toString().contains("UNREADABLE"));
    }

    @Test
    void records_moved_off_it_first_still_read() {
      shell.execute("write customer record #1");
      shell.execute("use ML-KEM-768");
      shell.execute("rewrap");

      shell.execute("retire RSA-OAEP-3072");
      shell.execute("read");

      assertTrue(output.toString().contains("nothing was lost"));
      assertTrue(output.toString().contains("record-0001 (ML-KEM-768) -> customer record #1"));
    }

    @Test
    void its_keys_are_disabled_in_the_kms() throws IOException {
      shell.execute("write customer record #1");
      shell.execute("use ML-KEM-768");

      shell.execute("retire RSA-OAEP-3072");

      assertTrue(
          ws.kms().listKeys().stream()
              .filter(key -> key.algorithm().equals("RSA-OAEP-3072"))
              .noneMatch(KeyMetadata::enabled));
    }

    @Test
    void the_algorithm_wrapping_new_data_cannot_be_retired() {
      shell.execute("retire RSA-OAEP-3072");

      assertTrue(output.toString().contains("is wrapping new data"));
    }

    @Test
    void enable_brings_the_records_back() {
      shell.execute("write customer record #1");
      shell.execute("use ML-KEM-768");
      shell.execute("retire RSA-OAEP-3072");

      shell.execute("enable RSA-OAEP-3072");
      shell.execute("read");

      assertTrue(output.toString().contains("record-0001 (RSA-OAEP-3072) -> customer record #1"));
    }

    @Test
    void use_refuses_it_rather_than_quietly_creating_a_new_key() throws IOException {
      shell.execute("write customer record #1");
      shell.execute("use ML-KEM-768");
      shell.execute("rewrap");
      shell.execute("retire RSA-OAEP-3072");

      shell.execute("use RSA-OAEP-3072");

      assertEquals("ML-KEM-768", shell.current());
      assertTrue(output.toString().contains("RSA-OAEP-3072 is retired"));
      assertTrue(
          ws.kms().listKeys().stream()
              .filter(key -> key.algorithm().equals("RSA-OAEP-3072"))
              .noneMatch(KeyMetadata::enabled));
    }

    @Test
    void a_new_session_that_starts_on_it_writes_nothing_until_another_is_chosen()
        throws IOException {
      shell.execute("write customer record #1");
      shell.execute("use ML-KEM-768");
      shell.execute("rewrap");
      shell.execute("retire RSA-OAEP-3072");
      var next = new Shell(ws, new PrintWriter(output));

      next.execute("write customer record #2");
      next.execute("use");

      assertEquals(1, ws.envelopes().all().size());
      assertTrue(output.toString().contains("RSA-OAEP-3072 is retired"));
      assertTrue(output.toString().contains("(retired)"));
    }

    @Test
    void enable_makes_it_usable_again() {
      shell.execute("write customer record #1");
      shell.execute("use ML-KEM-768");
      shell.execute("rewrap");
      shell.execute("retire RSA-OAEP-3072");
      shell.execute("enable RSA-OAEP-3072");

      shell.execute("use RSA-OAEP-3072");

      assertEquals("RSA-OAEP-3072", shell.current());
    }
  }

  @Nested
  class When_listing_algorithms {

    @Test
    void both_names_for_the_command_work() {
      shell.execute("algorithms");
      shell.execute("algs");

      assertEquals(2, output.toString().split("Key wrapping", -1).length - 1);
    }
  }

  @Nested
  class When_asking_for_help {

    @Test
    void both_names_list_the_commands() {
      shell.execute("help");
      shell.execute("?");

      assertEquals(2, output.toString().split("use \\[algorithm]", -1).length - 1);
    }
  }

  @Nested
  class When_an_algorithm_cannot_describe_itself {

    @Test
    void algorithms_lists_it_as_unknown_rather_than_failing() {
      var kms =
          LocalKms.withStandardAlgorithms(dataDir.resolve("kms"))
              .register(
                  KeyTypes.secretKey(
                      "EXPLODING", AesGcmWrapper::newKey, key -> new ExplodingWrapper()));
      shell = new Shell(new Workspace(dataDir, kms), new PrintWriter(output));

      shell.execute("algorithms");

      String row =
          output.toString().lines().filter(line -> line.contains("EXPLODING")).findFirst().get();
      assertTrue(row.contains("unknown"), row);
      assertFalse(output.toString().contains("error:"));
    }
  }

  @Nested
  class When_a_line_is_not_a_command {

    @Test
    void an_unknown_command_keeps_the_session_going() {
      assertTrue(shell.execute("frobnicate"));
    }

    @Test
    void a_blank_line_keeps_the_session_going() {
      assertTrue(shell.execute("   "));
    }

    @Test
    void an_unexpected_error_keeps_the_session_going() {
      var kms =
          LocalKms.withStandardAlgorithms(dataDir.resolve("kms"))
              .register(
                  KeyTypes.secretKey(
                      "EXPLODING", AesGcmWrapper::newKey, key -> new ExplodingWrapper()));
      shell = new Shell(new Workspace(dataDir, kms), new PrintWriter(output));
      shell.execute("use EXPLODING");

      assertTrue(shell.execute("write customer record #1"));
      assertTrue(output.toString().contains("unexpected error"));
    }

    @Test
    void a_record_number_too_large_to_exist_is_just_not_found() {
      assertTrue(shell.execute("show 99999999999"));
      assertTrue(output.toString().contains("no record called 99999999999"));
    }

    @Test
    void a_command_that_fails_keeps_the_session_going() {
      assertTrue(shell.execute("show record-0099"));
    }
  }

  @Nested
  class When_asked_to_leave {

    @Test
    void exit_ends_the_session() {
      assertFalse(shell.execute("exit"));
    }

    @Test
    void quit_ends_the_session() {
      assertFalse(shell.execute("quit"));
    }
  }

  @Nested
  class When_a_copied_envelope_is_named_by_path {

    @Test
    void it_is_selected_from_wherever_it_is() throws IOException {
      shell.execute("write customer record #1");
      Path original = dataDir.resolve("envelopes").resolve("record-0001.envelope");
      Path copy = Files.copy(original, dataDir.resolve("harvested.envelope"));

      List<Stored> selected = StoreCommands.select(ws, copy.toString());

      assertEquals("RSA-OAEP-3072", selected.getFirst().envelope().alg());
    }
  }

  /** Fails in a way nobody planned for, to prove one bad command cannot end the session. */
  private static final class ExplodingWrapper implements KeyWrapper {

    @Override
    public String algId() {
      return "EXPLODING";
    }

    @Override
    public WrappedDek wrap(SecretKey dek, byte[] aad) {
      throw new IllegalStateException("boom");
    }

    @Override
    public SecretKey unwrap(WrappedDek w, byte[] aad) {
      throw new IllegalStateException("boom");
    }
  }
}
