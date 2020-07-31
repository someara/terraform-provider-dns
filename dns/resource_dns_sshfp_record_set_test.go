package dns

import (
	"fmt"
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/helper/resource"
	"github.com/hashicorp/terraform-plugin-sdk/helper/schema"
	"github.com/hashicorp/terraform-plugin-sdk/terraform"
	"github.com/miekg/dns"
)

func TestAccDnsSSHFPRecordSet_Basic(t *testing.T) {

	var name, zone string
	resourceName := "dns_sshfp_record_set.foo"
	resourceRoot := "dns_sshfp_record_set.root"

	deleteSSHFPRecordSet := func() {
		meta := testAccProvider.Meta()

		msg := new(dns.Msg)

		msg.SetUpdate(zone)

		fqdn := testResourceFQDN(name, zone)

		rr_remove, _ := dns.NewRR(fmt.Sprintf("%s 0 SSHFP", fqdn))
		msg.RemoveRRset([]dns.RR{rr_remove})

		r, err := exchange(msg, true, meta)
		if err != nil {
			t.Fatalf("Error deleting DNS record: %s", err)
		}
		if r.Rcode != dns.RcodeSuccess {
			t.Fatalf("Error deleting DNS record: %v", r.Rcode)
		}
	}

	resource.Test(t, resource.TestCase{
		PreCheck:     func() { testAccPreCheck(t) },
		Providers:    testAccProviders,
		CheckDestroy: testAccCheckDnsSSHFPRecordSetDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccDnsSSHFPRecordSet_basic,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "sshfp.#", "1"),
					testAccCheckDnsSSHFPRecordSetExists(t, resourceName,
						[]interface{}{
							map[string]interface{}{
								"algorithm":   1,
								"type":        1,
								"fingerprint": "759135367dba7ecc03ebfae5daa2658c8c1bf6c0"}},
						&name,
						&zone),
				),
			},
			{
				Config: testAccDnsSSHFPRecordSet_update,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "sshfp.#", "3"),
					testAccCheckDnsSSHFPRecordSetExists(t, resourceName,
						[]interface{}{
							map[string]interface{}{
								"algorithm":   1,
								"type":        2,
								"fingerprint": "d04e4ffe3cccfa39e42aa478101b0333ae7d07859f32af729b2918984fa71c21"},
							map[string]interface{}{
								"algorithm":   3,
								"type":        1,
								"fingerprint": "6d2c02a6b8126d26229f5a784bf94ba5eddcf884"},
							map[string]interface{}{
								"algorithm":   3,
								"type":        2,
								"fingerprint": "c556789389b68753a98fa10f9756fd35367796bf4d628e5b0467f40ed8da40bd"}},
						&name,
						&zone),
				),
			},
			{
				PreConfig: deleteSSHFPRecordSet,
				Config:    testAccDnsSSHFPRecordSet_update,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "sshfp.#", "3"),
					testAccCheckDnsSSHFPRecordSetExists(t, resourceName,
						[]interface{}{
							map[string]interface{}{
								"algorithm":   1,
								"type":        2,
								"fingerprint": "d04e4ffe3cccfa39e42aa478101b0333ae7d07859f32af729b2918984fa71c21"},
							map[string]interface{}{
								"algorithm":   3,
								"type":        1,
								"fingerprint": "6d2c02a6b8126d26229f5a784bf94ba5eddcf884"},
							map[string]interface{}{
								"algorithm":   3,
								"type":        2,
								"fingerprint": "c556789389b68753a98fa10f9756fd35367796bf4d628e5b0467f40ed8da40bd"}},
						&name,
						&zone),
				),
			},
			{
				ResourceName:      resourceName,
				ImportState:       true,
				ImportStateVerify: true,
			},
			{
				Config: testAccDnsSSHFPRecordSet_root,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceRoot, "sshfp.#", "1"),
					testAccCheckDnsSSHFPRecordSetExists(t, resourceRoot,
						[]interface{}{

							map[string]interface{}{
								"algorithm":   4,
								"type":        2,
								"fingerprint": "e4bb7a4c9cbfdbd9ee862cd5736d404f5c53adefce91024948e876975cbd77b3"}},
						&name,
						&zone),
				),
			},
			{
				ResourceName:      resourceRoot,
				ImportState:       true,
				ImportStateVerify: true,
			},
		},
	})
}

func testAccCheckDnsSSHFPRecordSetDestroy(s *terraform.State) error {
	return testAccCheckDnsDestroy(s, "dns_sshfp_record_set", dns.TypeSSHFP)
}

func testAccCheckDnsSSHFPRecordSetExists(t *testing.T, n string, sshfp []interface{}, name, zone *string) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		rs, ok := s.RootModule().Resources[n]
		if !ok {
			return fmt.Errorf("Not found: %s", n)
		}
		if rs.Primary.ID == "" {
			return fmt.Errorf("No ID is set")
		}

		*name = rs.Primary.Attributes["name"]
		*zone = rs.Primary.Attributes["zone"]

		fqdn := testResourceFQDN(*name, *zone)

		meta := testAccProvider.Meta()

		msg := new(dns.Msg)
		msg.SetQuestion(fqdn, dns.TypeSSHFP)
		r, err := exchange(msg, false, meta)
		if err != nil {
			return fmt.Errorf("Error querying DNS record: %s", err)
		}
		if r.Rcode != dns.RcodeSuccess {
			return fmt.Errorf("Error querying DNS record")
		}

		existing := schema.NewSet(resourceDnsSSHFPRecordSetHash, nil)
		expected := schema.NewSet(resourceDnsSSHFPRecordSetHash, sshfp)
		for _, record := range r.Answer {
			switch r := record.(type) {
			case *dns.SSHFP:
				m := map[string]interface{}{
					"algorithm":   int(r.Algorithm),
					"type":        int(r.Type),
					"fingerprint": r.FingerPrint,
				}
				existing.Add(m)
			default:
				return fmt.Errorf("didn't get an MX record")
			}
		}
		if !existing.Equal(expected) {
			return fmt.Errorf("DNS record differs: expected %v, found %v", expected, existing)
		}
		return nil
	}
}

var testAccDnsSSHFPRecordSet_basic = fmt.Sprintf(`
  resource "dns_sshfp_record_set" "foo" {
    zone = "example.com."
    name = "foo"
    sshfp {
      algorithm = 1
      type = 1
      fingerprint = "759135367dba7ecc03ebfae5daa2658c8c1bf6c0"
    }
  }`)

var testAccDnsSSHFPRecordSet_update = fmt.Sprintf(`
  resource "dns_sshfp_record_set" "foo" {
    zone = "example.com."
    name = "foo"
    sshfp {
      algorithm = 1
      type = 2
      fingerprint = "d04e4ffe3cccfa39e42aa478101b0333ae7d07859f32af729b2918984fa71c21"
    }
    sshfp {
      algorithm = 3
      type = 1
      fingerprint = "6d2c02a6b8126d26229f5a784bf94ba5eddcf884"
    }
    sshfp {
      algorithm = 3
      type = 2
      fingerprint = "c556789389b68753a98fa10f9756fd35367796bf4d628e5b0467f40ed8da40bd"
    }
  }`)

var testAccDnsSSHFPRecordSet_root = fmt.Sprintf(`
  resource "dns_sshfp_record_set" "root" {
    zone = "example.com."
    ttl = 300
    sshfp {
      algorithm = 4
      type = 2
      fingerprint = "e4bb7a4c9cbfdbd9ee862cd5736d404f5c53adefce91024948e876975cbd77b3"
    }
  }`)
