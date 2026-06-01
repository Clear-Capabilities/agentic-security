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
