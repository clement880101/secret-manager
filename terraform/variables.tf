variable "aws_region" {
  description = "AWS region to deploy resources into."
  type        = string
  default     = "us-west-1"
}


variable "enable_https" {
  description = <<-EOT
    Put a CloudFront distribution in front of the load balancer so clients can
    reach the API over HTTPS. Enabled by default: without it every request,
    including the GitHub access token and every secret value, crosses the
    internet in cleartext.

    CloudFront serves a certificate for its own *.cloudfront.net hostname at no
    cost and with no domain of your own, which is why this works out of the box
    for any deployment. ACM will not issue a certificate for an AWS-owned load
    balancer hostname, so terminating TLS on the load balancer instead would
    require you to own a domain.
  EOT
  type        = bool
  default     = true
}

variable "domain_name" {
  description = <<-EOT
    Optional custom hostname to serve the API on, for example
    secrets.example.com. Leave empty to use the CloudFront hostname.

    Requires acm_certificate_arn, and you create the DNS record pointing at the
    distribution yourself.
  EOT
  type        = string
  default     = ""
}

variable "acm_certificate_arn" {
  description = <<-EOT
    ARN of an ACM certificate covering domain_name. CloudFront only accepts
    certificates issued in us-east-1, regardless of where the rest of this
    stack runs. Required when domain_name is set.
  EOT
  type        = string
  default     = ""
}


