// R18 — semantic IaC (Terraform) tests. The differentiator: variable resolution.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { scanTerraform } from '../src/sast/iac-terraform.js';

test('open ingress via a LITERAL cidr fires', () => {
  const tf = `resource "aws_security_group" "x" {\n  ingress { cidr_blocks = ["0.0.0.0/0"] }\n}`;
  const f = scanTerraform('main.tf', tf);
  assert.ok(f.some(x => /open to the world/.test(x.vuln)));
});

test('open ingress via a VARIABLE default fires (the regex blind spot)', () => {
  const tf = `
    variable "ingress_cidr" { default = "0.0.0.0/0" }
    resource "aws_security_group" "x" {
      ingress { cidr_blocks = [var.ingress_cidr] }
    }`;
  const f = scanTerraform('main.tf', tf);
  assert.equal(f.length, 1);
  assert.match(f[0].description, /via `ingress_cidr`/);
});

// Stage 4 correctness audit: the open-ingress check's attr regex matches
// `cidr_blocks = [...]` anywhere in the file, with no awareness of whether
// it's nested inside an `ingress { }` or `egress { }` block. An egress rule
// allowing 0.0.0.0/0 (outbound to anywhere) is the standard, expected
// default for nearly every AWS security group — it's an ingress rule doing
// the same that's the actual exposure. The rule's own name and vuln text
// ("ingress open to the world") only claim to check ingress.
test('egress cidr_blocks = 0.0.0.0/0 (normal, safe outbound rule) does NOT fire the ingress check', () => {
  const tf = `resource "aws_security_group" "x" {\n  egress { cidr_blocks = ["0.0.0.0/0"] }\n}`;
  const f = scanTerraform('main.tf', tf);
  assert.equal(f.filter(x => /open to the world/.test(x.vuln)).length, 0,
    `expected the egress-only rule to be silent; got ${JSON.stringify(f.map(x => x.vuln))}`);
});

test('public S3 ACL via variable fires', () => {
  const tf = `
    variable "acl" { default = "public-read" }
    resource "aws_s3_bucket_acl" "b" { acl = var.acl }`;
  assert.ok(scanTerraform('s3.tf', tf).some(x => /S3 bucket ACL is public/.test(x.vuln)));
});

test('publicly_accessible db fires', () => {
  const tf = `resource "aws_db_instance" "d" { publicly_accessible = true }`;
  assert.ok(scanTerraform('db.tf', tf).some(x => /publicly accessible/.test(x.vuln)));
});

test('precision: restricted cidr and private acl do NOT fire', () => {
  const tf = `
    variable "ingress_cidr" { default = "10.0.0.0/8" }
    resource "aws_security_group" "x" { ingress { cidr_blocks = [var.ingress_cidr, "192.168.0.0/16"] } }
    resource "aws_s3_bucket_acl" "b" { acl = "private" }
    resource "aws_db_instance" "d" { publicly_accessible = false }`;
  assert.equal(scanTerraform('main.tf', tf).length, 0);
});

test('precision: non-.tf file is ignored', () => {
  assert.equal(scanTerraform('x.json', `cidr_blocks = ["0.0.0.0/0"]`).length, 0);
});
