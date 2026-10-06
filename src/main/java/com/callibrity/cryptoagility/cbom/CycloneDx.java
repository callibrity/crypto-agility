package com.callibrity.cryptoagility.cbom;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonValue;
import tools.jackson.databind.SerializationFeature;
import tools.jackson.databind.json.JsonMapper;

import java.util.List;

/**
 * The slice of the CycloneDX 1.6 bill-of-materials format that a cryptographic
 * inventory (CBOM) needs, as plain records. Field names match the schema, so
 * Jackson writes them out as they are; the few that are not legal Java names
 * are renamed with @JsonProperty. Empty optional fields are left out.
 * <p>
 * The full format is much larger. The official library, cyclonedx-core-java,
 * models all of it.
 *
 * @see <a href="https://cyclonedx.org/docs/1.6/json/">CycloneDX 1.6 JSON reference</a>
 */
public final class CycloneDx {

    public static final String SCHEMA = "http://cyclonedx.org/schema/bom-1.6.schema.json";
    public static final String SPEC_VERSION = "1.6";

    private static final JsonMapper MAPPER = JsonMapper.builder().enable(SerializationFeature.INDENT_OUTPUT).build();

    private CycloneDx() {}

    /** The document as JSON. */
    public static String toJson(Bom bom) {
        return MAPPER.writeValueAsString(bom) + "\n";
    }

    @JsonInclude(JsonInclude.Include.NON_NULL)
    public record Bom(@JsonProperty("$schema") String schema, String bomFormat, String specVersion,
                      String serialNumber, int version, Metadata metadata, List<Component> components,
                      List<Dependency> dependencies) {

        public static Bom of(String serialNumber, Metadata metadata, List<Component> components,
                             List<Dependency> dependencies) {
            return new Bom(SCHEMA, "CycloneDX", SPEC_VERSION, serialNumber, 1, metadata, components, dependencies);
        }
    }

    /** When the inventory was taken, by what, and of what. */
    @JsonInclude(JsonInclude.Include.NON_NULL)
    public record Metadata(String timestamp, Tools tools, Component component) {}

    @JsonInclude(JsonInclude.Include.NON_NULL)
    public record Tools(List<Component> components) {}

    /** One thing in the inventory: here, an algorithm, a key, the data store, or the tool itself. */
    @JsonInclude(JsonInclude.Include.NON_NULL)
    public record Component(ComponentType type, @JsonProperty("bom-ref") String bomRef, String name,
                            String description, CryptoProperties cryptoProperties, List<Property> properties) {

        public static Component cryptographicAsset(String bomRef, String name, CryptoProperties crypto,
                                                   List<Property> properties) {
            return new Component(ComponentType.CRYPTOGRAPHIC_ASSET, bomRef, name, null, crypto, properties);
        }
    }

    public enum ComponentType {
        APPLICATION("application"), DATA("data"), CRYPTOGRAPHIC_ASSET("cryptographic-asset");

        private final String json;

        ComponentType(String json) {
            this.json = json;
        }

        @JsonValue
        public String json() {
            return json;
        }
    }

    /** Exactly one of the two property groups is set, matching assetType. */
    @JsonInclude(JsonInclude.Include.NON_NULL)
    public record CryptoProperties(AssetType assetType, AlgorithmProperties algorithmProperties,
                                   RelatedCryptoMaterialProperties relatedCryptoMaterialProperties, String oid) {

        public static CryptoProperties algorithm(AlgorithmProperties properties, String oid) {
            return new CryptoProperties(AssetType.ALGORITHM, properties, null, oid);
        }

        public static CryptoProperties keyMaterial(RelatedCryptoMaterialProperties properties) {
            return new CryptoProperties(AssetType.RELATED_CRYPTO_MATERIAL, null, properties, null);
        }
    }

    public enum AssetType {
        ALGORITHM("algorithm"), RELATED_CRYPTO_MATERIAL("related-crypto-material");

        private final String json;

        AssetType(String json) {
            this.json = json;
        }

        @JsonValue
        public String json() {
            return json;
        }
    }

    /**
     * What an algorithm is. primitive takes the schema's values, such as "kem",
     * "pke", "ae", "block-cipher" or "combiner". nistQuantumSecurityLevel runs
     * from 0, broken by a quantum computer, to 6.
     */
    @JsonInclude(JsonInclude.Include.NON_NULL)
    public record AlgorithmProperties(String primitive, String parameterSetIdentifier, String curve, String mode,
                                      String padding, List<String> cryptoFunctions, Integer classicalSecurityLevel,
                                      Integer nistQuantumSecurityLevel) {

        public static AlgorithmProperties unknown() {
            return new AlgorithmProperties("unknown", null, null, null, null, null, null, null);
        }
    }

    /** A key, and the algorithm it belongs to. */
    @JsonInclude(JsonInclude.Include.NON_NULL)
    public record RelatedCryptoMaterialProperties(KeyType type, String id, String algorithmRef, String state,
                                                  String creationDate) {}

    public enum KeyType {
        KEY("key"), PUBLIC_KEY("public-key"), PRIVATE_KEY("private-key"), SECRET_KEY("secret-key");

        private final String json;

        KeyType(String json) {
            this.json = json;
        }

        @JsonValue
        public String json() {
            return json;
        }
    }

    /** A name-value pair for anything the schema has no field for. */
    public record Property(String name, String value) {}

    /** Says that one component relies on others: the store on its algorithms, an algorithm on its keys. */
    public record Dependency(String ref, List<String> dependsOn) {}
}
