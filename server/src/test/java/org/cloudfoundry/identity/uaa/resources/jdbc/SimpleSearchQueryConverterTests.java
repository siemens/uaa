package org.cloudfoundry.identity.uaa.resources.jdbc;

import com.unboundid.scim.sdk.InvalidResourceException;
import org.cloudfoundry.identity.uaa.test.ModelTestUtils;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.util.MultiValueMap;

import java.util.Arrays;
import java.util.List;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.*;
import static org.junit.jupiter.api.Assertions.*;

class SimpleSearchQueryConverterTests {

    private SimpleSearchQueryConverter converter;

    @BeforeEach
    void setup() {
        converter = new SimpleSearchQueryConverter();
    }

    @Test
    void testQuery() {
        String query = ModelTestUtils.getResourceAsString(this.getClass(), "testQuery.scimFilter");

        String message =
                assertThrows(InvalidResourceException.class, () -> converter.scimFilter(query))
                        .getMessage();

        assertThat(message, startsWith("Invalid filter attributes"));
        assertThat(message, containsString("an/**/invalid/**/attribute/**/and/**/1"));
        assertThat(message, containsString("1"));
        assertThat(message, containsString("\"1\""));
    }

    @ParameterizedTest
    @ValueSource(strings = {
            "origin eq \"origin-value\" and externalGroup eq \"group-value\"",
            "externalGroup eq \"group-value\" and origin eq \"origin-value\""
    })
    void simpleValueExtract(final String query) {
        MultiValueMap<String, Object> result = converter.getFilterValues(query, Arrays.asList("origin", "externalGroup".toLowerCase()));
        assertNotNull(result);
        assertEquals(2, result.size());

        assertNotNull(result.get("origin"));
        assertEquals(1, result.get("origin").size());
        assertEquals("origin-value", result.get("origin").get(0));

        assertNotNull(result.get("externalGroup"));
        assertEquals(1, result.get("externalGroup").size());
        assertEquals("group-value", result.get("externalGroup").get(0));
    }

    @Test
    void invalidFilterAttribute() {
        String query = "origin eq \"origin-value\" and externalGroup eq \"group-value\"";

        String message = assertThrows(IllegalArgumentException.class,
                () -> converter.getFilterValues(query, Arrays.asList("origin", "externalGroup"))).getMessage();

        assertThat(message, is("Invalid filter attributes:externalGroup"));
    }

    @Test
    void invalidConditionalOr() {
        String query = "origin eq \"origin-value\" or externalGroup eq \"group-value\"";
        List<String> validAttributes = Arrays.asList("origin", "externalGroup".toLowerCase());
        String message = assertThrows(IllegalArgumentException.class,
                () -> converter.getFilterValues(query, validAttributes)).getMessage();

        assertThat(message, is("[or] operator is not supported."));
    }

    @Test
    void invalidConditionalPr() {
        String query = "origin eq \"origin-value\" and externalGroup pr";
        List<String> validAttributes = Arrays.asList("origin", "externalGroup".toLowerCase());
        String message = assertThrows(IllegalArgumentException.class,
                () -> converter.getFilterValues(query, validAttributes)).getMessage();

        assertThat(message, is("[pr] operator is not supported."));
    }

    @ParameterizedTest
    @ValueSource(strings = {"co", "sw", "ge", "gt", "lt", "le"})
    void invalidOperator(final String operator) {
        String query = "origin eq \"origin-value\" and externalGroup " + operator + " \"group-value\"";
        List<String> validAttributes = Arrays.asList("origin", "externalGroup".toLowerCase());
        String message = assertThrows(IllegalArgumentException.class,
                () -> converter.getFilterValues(query, validAttributes)).getMessage();

        assertThat(message, is("[" + operator + "] operator is not supported."));
    }
}