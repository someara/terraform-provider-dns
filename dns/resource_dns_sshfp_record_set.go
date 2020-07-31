package dns

import (
	"bytes"
	"fmt"
	"sort"

	"github.com/hashicorp/terraform-plugin-sdk/helper/hashcode"
	"github.com/hashicorp/terraform-plugin-sdk/helper/schema"
	"github.com/miekg/dns"
)

func resourceDnsSSHFPRecordSet() *schema.Resource {
	return &schema.Resource{
		Create: resourceDnsSSHFPRecordSetCreate,
		Read:   resourceDnsSSHFPRecordSetRead,
		Update: resourceDnsSSHFPRecordSetUpdate,
		Delete: resourceDnsSSHFPRecordSetDelete,
		Importer: &schema.ResourceImporter{
			State: resourceDnsImport,
		},

		Schema: map[string]*schema.Schema{
			"zone": &schema.Schema{
				Type:         schema.TypeString,
				Required:     true,
				ForceNew:     true,
				ValidateFunc: validateZone,
			},
			"name": &schema.Schema{
				Type:         schema.TypeString,
				Optional:     true,
				ForceNew:     true,
				ValidateFunc: validateName,
			},
			"sshfp": &schema.Schema{
				Type:     schema.TypeSet,
				Required: true,
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"algorithm": {
							Type:     schema.TypeInt,
							Required: true,
						},
						"type": {
							Type:     schema.TypeInt,
							Required: true,
						},
						"fingerprint": {
							Type:     schema.TypeString,
							Required: true,
						},
					},
				},
				Set: resourceDnsSSHFPRecordSetHash,
			},
			"ttl": &schema.Schema{
				Type:     schema.TypeInt,
				Optional: true,
				ForceNew: true,
				Default:  3600,
			},
		},
	}
}

func resourceDnsSSHFPRecordSetCreate(d *schema.ResourceData, meta interface{}) error {

	d.SetId(resourceFQDN(d))

	return resourceDnsSSHFPRecordSetUpdate(d, meta)
}

func resourceDnsSSHFPRecordSetRead(d *schema.ResourceData, meta interface{}) error {

	answers, err := resourceDnsRead(d, meta, dns.TypeSSHFP)
	if err != nil {
		return err
	}

	if len(answers) > 0 {

		var ttl sort.IntSlice

		sshfp := schema.NewSet(resourceDnsSSHFPRecordSetHash, nil)
		for _, record := range answers {
			switch r := record.(type) {
			case *dns.SSHFP:
				m := map[string]interface{}{
					"algorithm":   int(r.Algorithm),
					"type":        int(r.Type),
					"fingerprint": r.FingerPrint,
				}
				sshfp.Add(m)
				ttl = append(ttl, int(r.Hdr.Ttl))
			default:
				return fmt.Errorf("didn't get an SSHFP record")
			}
		}
		sort.Sort(ttl)

		d.Set("sshfp", sshfp)
		d.Set("ttl", ttl[0])
	} else {
		d.SetId("")
	}

	return nil
}

func resourceDnsSSHFPRecordSetUpdate(d *schema.ResourceData, meta interface{}) error {

	if meta != nil {

		ttl := d.Get("ttl").(int)
		fqdn := resourceFQDN(d)

		msg := new(dns.Msg)

		msg.SetUpdate(d.Get("zone").(string))

		if d.HasChange("sshfp") {
			o, n := d.GetChange("sshfp")
			os := o.(*schema.Set)
			ns := n.(*schema.Set)
			remove := os.Difference(ns).List()
			add := ns.Difference(os).List()

			// Loop through all the old addresses and remove them
			for _, sshfp := range remove {
				m := sshfp.(map[string]interface{})
				rr_remove, _ := dns.NewRR(fmt.Sprintf("%s %d SSHFP %d %d %s", fqdn, ttl, m["algorithm"], m["type"], m["fingerprint"]))
				msg.Remove([]dns.RR{rr_remove})
			}
			// Loop through all the new addresses and insert them
			for _, sshfp := range add {
				m := sshfp.(map[string]interface{})
				rr_insert, _ := dns.NewRR(fmt.Sprintf("%s %d SSHFP %d %d %s", fqdn, ttl, m["algorithm"], m["type"], m["fingerprint"]))
				msg.Insert([]dns.RR{rr_insert})
			}

			r, err := exchange(msg, true, meta)
			if err != nil {
				d.SetId("")
				return fmt.Errorf("Error updating DNS record: %s", err)
			}
			if r.Rcode != dns.RcodeSuccess {
				d.SetId("")
				return fmt.Errorf("Error updating DNS record: %v (%s)", r.Rcode, dns.RcodeToString[r.Rcode])
			}
		}

		return resourceDnsSSHFPRecordSetRead(d, meta)
	} else {
		return fmt.Errorf("update server is not set")
	}
}

func resourceDnsSSHFPRecordSetDelete(d *schema.ResourceData, meta interface{}) error {

	return resourceDnsDelete(d, meta, dns.TypeSSHFP)
}

func resourceDnsSSHFPRecordSetHash(v interface{}) int {
	var buf bytes.Buffer
	m := v.(map[string]interface{})
	buf.WriteString(fmt.Sprintf("%d-", m["algorithm"].(int)))
	buf.WriteString(fmt.Sprintf("%d-", m["type"].(int)))
	buf.WriteString(fmt.Sprintf("%s-", m["fingerprint"].(string)))

	return hashcode.String(buf.String())
}
