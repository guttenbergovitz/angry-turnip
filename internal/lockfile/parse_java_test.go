package lockfile

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestParsePomXml verifies parsing of Maven pom.xml.
func TestParsePomXml(t *testing.T) {
	pomPath := filepath.Join("..", "..", "test-project", "java", "pom.xml")
	file, err := os.Open(pomPath)
	if err != nil {
		t.Fatalf("failed to open pom.xml: %v", err)
	}
	defer file.Close()

	deps, err := ParsePomXml(file)
	if err != nil {
		t.Fatalf("ParsePomXml returned error: %v", err)
	}

	if len(deps.Production) != 2 {
		t.Errorf("expected 2 production dependencies in pom.xml, got %d", len(deps.Production))
	}
	if len(deps.Development) != 1 {
		t.Errorf("expected 1 dev dependency in pom.xml, got %d", len(deps.Development))
	}

	if version, ok := deps.Production["org.apache.logging.log4j:log4j-core"]; !ok || version != "2.14.1" {
		t.Errorf("expected log4j-core version 2.14.1, got %q", version)
	}

	if version, ok := deps.Production["org.springframework:spring-core"]; !ok || version != "5.3.20" {
		t.Errorf("expected spring-core version 5.3.20, got %q", version)
	}

	if version, ok := deps.Development["junit:junit"]; !ok || version != "4.13.2" {
		t.Errorf("expected junit version 4.13.2, got %q", version)
	}
}

// TestParseGradleLockfile verifies parsing of gradle.lockfile.
func TestParseGradleLockfile(t *testing.T) {
	gradlePath := filepath.Join("..", "..", "test-project", "java", "gradle.lockfile")
	file, err := os.Open(gradlePath)
	if err != nil {
		t.Fatalf("failed to open gradle.lockfile: %v", err)
	}
	defer file.Close()

	deps, err := ParseGradleLockfile(file)
	if err != nil {
		t.Fatalf("ParseGradleLockfile returned error: %v", err)
	}

	if len(deps.Production) != 2 {
		t.Errorf("expected 2 production dependencies in gradle.lockfile, got %d", len(deps.Production))
	}
	if len(deps.Development) != 1 {
		t.Errorf("expected 1 dev dependency in gradle.lockfile, got %d", len(deps.Development))
	}

	if version, ok := deps.Production["org.apache.logging.log4j:log4j-core"]; !ok || version != "2.14.1" {
		t.Errorf("expected log4j-core version 2.14.1, got %q", version)
	}
}

func TestParsePomXmlDependencyManagementAndUnresolved(t *testing.T) {
	pomContent := `<?xml version="1.0" encoding="UTF-8"?>
<project>
  <parent>
    <groupId>com.example</groupId>
    <artifactId>parent-pom</artifactId>
    <version>3.2.1</version>
  </parent>
  <properties>
    <jackson.version>2.15.2</jackson.version>
  </properties>
  <dependencyManagement>
    <dependencies>
      <dependency>
        <groupId>com.fasterxml.jackson.core</groupId>
        <artifactId>jackson-databind</artifactId>
        <version>${jackson.version}</version>
      </dependency>
    </dependencies>
  </dependencyManagement>
  <dependencies>
    <dependency>
      <groupId>com.fasterxml.jackson.core</groupId>
      <artifactId>jackson-databind</artifactId>
    </dependency>
    <dependency>
      <groupId>${project.groupId}</groupId>
      <artifactId>internal-lib</artifactId>
      <version>${project.version}</version>
    </dependency>
    <dependency>
      <groupId>org.springframework.boot</groupId>
      <artifactId>spring-boot-starter-web</artifactId>
    </dependency>
  </dependencies>
</project>`

	deps, err := ParsePomXml(strings.NewReader(pomContent))
	if err != nil {
		t.Fatalf("ParsePomXml returned error: %v", err)
	}

	if got := deps.Production["com.fasterxml.jackson.core:jackson-databind"]; got != "2.15.2" {
		t.Errorf("expected managed jackson-databind 2.15.2, got %q", got)
	}
	if got := deps.Production["com.example:internal-lib"]; got != "3.2.1" {
		t.Errorf("expected parent-resolved internal-lib 3.2.1, got %q", got)
	}
	if len(deps.Unresolved) != 1 || deps.Unresolved[0] != "org.springframework.boot:spring-boot-starter-web" {
		t.Errorf("expected unresolved spring-boot-starter-web, got %v", deps.Unresolved)
	}
}
