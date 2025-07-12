# --- Variables for the Lambda Module ---

# This variable receives the outputs from your naming convention module
variable "naming_module_outputs" {
  description = "Outputs from the bright_naming_conventions module containing name, tags, etc."
  type = object({
    app_group  = string
    env        = string
    instance   = string
    ledger     = string
    log_prefix = string
    purpose    = string
    region     = string
    tier       = string
    type       = string
    zone       = string
    name       = string # The generated resource name (e.g., ue1devlmbapimy-service001)
    tags       = map(string) # The generated standard tags
    log_path   = string
  })
}

variable "create" {
  type        = bool
  description = "Whether to create the Lambda resource."
  default     = true
}

variable "putin_khuylo" { # Assuming this is a control variable from your context
  type        = bool
  description = "A control variable for resource creation."
  default     = true
}

variable "local_existing_package" {
  type        = string
  default     = null
  description = "Path to a local existing Lambda deployment package."
}

variable "store_on_s3" {
  type        = bool
  default     = false
  description = "Whether to store the Lambda package on S3."
}

variable "s3_bucket" {
  type        = string
  default     = null
  description = "S3 bucket for Lambda package storage. Required if store_on_s3 is true."
}

variable "s3_prefix" {
  type        = string
  default     = null
  description = "S3 prefix for the Lambda package key. Optional."
}

variable "s3_existing_package" {
  type        = map(string)
  default     = null
  description = "Map containing details of an existing S3 package (bucket, key, version_id). Use if package already exists on S3."
}

variable "create_function" {
  type        = bool
  default     = true
  description = "Whether to create the Lambda function."
}

variable "create_layer" {
  type        = bool
  default     = false
  description = "Whether to create a Lambda layer."
}

# The 'function_name' and 'layer_name' variables will now be largely overridden
# by the 'naming_module_outputs.name' but are kept for module flexibility.
variable "function_name" {
  type        = string
  default     = null
  description = "Name of the Lambda function. Will be derived from naming_module_outputs.name if provided."
}

variable "description" {
  type        = string
  default     = "Managed by Terraform"
  description = "Description for the Lambda function or layer."
}

variable "create_role" {
  type        = bool
  default     = true
  description = "Whether to create the IAM role for Lambda. If false, lambda_role must be provided."
}

variable "lambda_role" {
  type        = string
  default     = null # If create_role is false, this should be the ARN
  description = "ARN of an existing Lambda IAM role if not created by this module."
}

variable "handler" {
  type        = string
  default     = "index.handler"
  description = "Lambda handler (for Zip packages). Not used for Image packages."
}

variable "memory_size" {
  type        = number
  default     = 128
  description = "Memory size for the Lambda function in MBs."
}

variable "reserved_concurrent_executions" {
  type        = number
  default     = -1
  description = "Reserved concurrent executions for the Lambda function. Set to -1 for no reservation."
}

variable "runtime" {
  type        = string
  default     = "nodejs18.x"
  description = "Lambda runtime (for Zip packages). Not used for Image packages."
}

variable "layers" {
  type        = list(string)
  default     = []
  description = "List of Lambda layer ARNs to attach to the function."
}

variable "lambda_at_edge" {
  type        = bool
  default     = false
  description = "Whether this is a Lambda@Edge function. Affects region and timeout constraints."
}

variable "timeout" {
  type        = number
  default     = 3
  description = "Timeout for the Lambda function in seconds."
}

variable "publish" {
  type        = bool
  default     = false
  description = "Whether to publish a new version of the Lambda function on deployment."
}

variable "kms_key_arn" {
  type        = string
  default     = null
  description = "KMS Key ARN for Lambda environment variables encryption."
}

variable "image_uri" {
  type        = string
  default     = null
  description = "ECR image URI for container-based Lambda function. Required if package_type is Image."
}

variable "package_type" {
  type        = string
  default     = "Zip"
  description = "Lambda package type (Zip or Image)."
  validation {
    condition     = contains(["Zip", "Image"], var.package_type)
    error_message = "Package type must be 'Zip' or 'Image'."
  }
}

variable "architectures" {
  type        = list(string)
  default     = ["x86_64"]
  description = "Lambda function architectures. Default is ['x86_64']."
}

variable "code_signing_config_arn" {
  type        = string
  default     = null
  description = "Code Signing Configuration ARN for Lambda."
}

variable "replace_security_groups_on_destroy" {
  type        = bool
  default     = false
  description = "Whether to replace security groups on destroy."
}

variable "replacement_security_group_ids" {
  type        = list(string)
  default     = []
  description = "Replacement security group IDs for replace_security_groups_on_destroy."
}

variable "skip_destroy" {
  type        = bool
  default     = false
  description = "Whether to skip destroy for the Lambda function. Prevents Terraform from destroying the resource."
}

variable "ephemeral_storage_size" {
  type        = number
  default     = null
  description = "Ephemeral storage size for Lambda in MBs. Not supported in all regions (e.g., GovCloud)."
}

variable "ignore_source_code_hash" {
  type        = bool
  default     = false
  description = "Whether to ignore source code hash for updates. Useful for manual updates or external build processes."
}

variable "image_config_entry_point" {
  type        = list(string)
  default     = []
  description = "Entry point for image-based Lambda. Overrides Dockerfile ENTRYPOINT."
}

variable "image_config_command" {
  type        = list(string)
  default     = []
  description = "Command for image-based Lambda. Overrides Dockerfile CMD."
}

variable "image_config_working_directory" {
  type        = string
  default     = null
  description = "Working directory for image-based Lambda."
}

variable "environment_variables" {
  type        = map(string)
  default     = {}
  description = "Environment variables for the Lambda function."
}

variable "dead_letter_target_arn" {
  type        = string
  default     = null
  description = "Dead-letter queue (SQS) or topic (SNS) ARN for asynchronous invocations."
}

variable "tracing_mode" {
  type        = string
  default     = null
  description = "Tracing mode for Lambda (e.g., Active, PassThrough). Set to null to disable."
}

variable "vpc_subnet_ids" {
  type        = list(string)
  default     = null
  description = "List of subnet IDs for VPC configuration. Required for VPC-enabled Lambda."
}

variable "vpc_security_group_ids" {
  type        = list(string)
  default     = null
  description = "List of security group IDs for VPC configuration. Required for VPC-enabled Lambda."
}

variable "ipv6_allowed_for_dual_stack" {
  type        = bool
  default     = false
  description = "Whether IPv6 is allowed for dual-stack VPC. (Lambda VPC support required)."
}

variable "file_system_arn" {
  type        = string
  default     = null
  description = "ARN of EFS file system to mount."
}

variable "file_system_local_mount_path" {
  type        = string
  default     = null
  description = "Local mount path for EFS."
}

variable "snap_start" {
  type        = bool
  default     = false
  description = "Whether to enable SnapStart for Java functions."
}

variable "logging_log_group" {
  type        = string
  default     = null
  description = "Name of the CloudWatch log group. If null, a default will be created based on function name."
}

variable "logging_log_format" {
  type        = string
  default     = "JSON"
  description = "Log format for Lambda logging (JSON, Text)."
  validation {
    condition     = contains(["JSON", "Text"], var.logging_log_format)
    error_message = "Log format must be 'JSON' or 'Text'."
  }
}

variable "logging_application_log_level" {
  type        = string
  default     = "INFO"
  description = "Application log level for Lambda logging (only for JSON format)."
}

variable "logging_system_log_level" {
  type        = string
  default     = "INFO"
  description = "System log level for Lambda logging (only for JSON format)."
}

variable "timeouts" {
  type        = map(string)
  default     = {}
  description = "Timeouts for Lambda resource operations (create, update, delete)."
}

variable "include_default_tag" {
  type        = bool
  default     = true
  description = "Whether to include a 'terraform-aws-modules' default tag."
}

# The 'tags' variable in this module can be used to pass additional,
# non-standardized tags that are not part of the naming convention.
# All standard tags come from 'naming_module_outputs.tags'.
variable "tags" {
  type        = map(string)
  default     = {}
  description = "Additional custom tags to merge with the standard tags."
}

variable "function_tags" {
  type        = map(string)
  default     = {}
  description = "Tags specific to the Lambda function resource (merged with standard and 'tags')."
}

variable "layer_name" {
  type        = string
  default     = null
  description = "Name of the Lambda layer. Will be derived from naming_module_outputs.name if provided."
}

variable "license_info" {
  type        = string
  default     = null
  description = "License information for the Lambda layer."
}

variable "compatible_runtimes" {
  type        = list(string)
  default     = []
  description = "Compatible runtimes for the Lambda layer. If empty, derived from function runtime."
}

variable "compatible_architectures" {
  type        = list(string)
  default     = []
  description = "Compatible architectures for the Lambda layer."
}

variable "layer_skip_destroy" {
  type        = bool
  default     = false
  description = "Whether to skip destroy for the Lambda layer."
}

variable "create_package" {
  type        = bool
  default     = true
  description = "Whether to create the Lambda package (zip or image)."
}

variable "s3_acl" {
  type        = string
  default     = "private"
  description = "ACL for the S3 object storing the Lambda package."
}

variable "s3_object_storage_class" {
  type        = string
  default     = "STANDARD"
  description = "Storage class for the S3 object storing the Lambda package."
}

variable "s3_server_side_encryption" {
  type        = string
  default     = "AES256"
  description = "Server-side encryption for S3 object storing the Lambda package."
}

variable "s3_kms_key_id" {
  type        = string
  default     = null
  description = "KMS Key ID for S3 object encryption if using SSE-KMS."
}

variable "s3_object_tags_only" {
  type        = bool
  default     = false
  description = "Whether to apply only s3_object_tags and override all other tags on the S3 object."
}

variable "s3_object_tags" {
  type        = map(string)
  default     = {}
  description = "Tags specific to the S3 object storing the Lambda package."
}

variable "s3_object_override_default_tags" {
  type        = bool
  default     = false
  description = "Whether to override default tags for S3 object provider."
}

variable "use_existing_cloudwatch_log_group" {
  type        = bool
  default     = false
  description = "Whether to use an existing CloudWatch log group or create a new one."
}

variable "cloudwatch_logs_retention_in_days" {
  type        = number
  default     = 30
  description = "CloudWatch logs retention in days for the Lambda log group."
}

variable "cloudwatch_logs_kms_key_id" {
  type        = string
  default     = null
  description = "KMS Key ID for CloudWatch logs encryption."
}

variable "cloudwatch_logs_skip_destroy" {
  type        = bool
  default     = false
  description = "Whether to skip destroy for CloudWatch log group."
}

variable "cloudwatch_logs_log_group_class" {
  type        = string
  default     = "STANDARD"
  description = "Log group class for CloudWatch logs."
}

variable "cloudwatch_logs_tags" {
  type        = map(string)
  default     = {}
  description = "Tags specific to the CloudWatch log group."
}

variable "provisioned_concurrent_executions" {
  type        = number
  default     = -1
  description = "Provisioned concurrent executions. Set to -1 to disable."
}

variable "create_current_version_async_event_config" {
  type        = bool
  default     = false
  description = "Whether to create async event config for current version."
}

variable "create_unqualified_alias_async_event_config" {
  type        = bool
  default     = false
  description = "Whether to create async event config for unqualified alias."
}

variable "create_async_event_config" {
  type        = bool
  default     = false
  description = "Whether to create async event config."
}

variable "maximum_event_age_in_seconds" {
  type        = number
  default     = null
  description = "Maximum event age in seconds for async invocations."
}

variable "maximum_retry_attempts" {
  type        = number
  default     = null
  description = "Maximum retry attempts for async invocations."
}

variable "destination_on_failure" {
  type        = string
  default     = null
  description = "Destination ARN for failed async invocations."
}

variable "destination_on_success" {
  type        = string
  default     = null
  description = "Destination ARN for successful async invocations."
}

variable "allowed_triggers" {
  type = map(object({
    statement_id         = optional(string)
    action               = optional(string)
    principal            = optional(string)
    principal_org_id     = optional(string)
    service              = optional(string) # Custom attribute to help build principal
    source_arn           = optional(string)
    source_account       = optional(string)
    event_source_token   = optional(string)
    function_url_auth_type = optional(string)
  }))
  default     = {}
  description = "Map of allowed triggers (permissions) for the Lambda function."
}

variable "create_current_version_allowed_triggers" {
  type        = bool
  default     = true
  description = "Whether to create allowed triggers for the current version ($LATEST)."
}

variable "create_unqualified_alias_allowed_triggers" {
  type        = bool
  default     = false
  description = "Whether to create allowed triggers for unqualified alias."
}

variable "event_source_mapping" {
  type        = map(any) # More specific object type is ideal here
  default     = {}
  description = "Map of event source mappings for Lambda triggers (e.g., SQS, Kinesis, DynamoDB)."
}

variable "create_lambda_function_url" {
  type        = bool
  default     = false
  description = "Whether to create a Lambda Function URL."
}

variable "create_unqualified_alias_lambda_function_url" {
  type        = bool
  default     = false
  description = "Whether to create a Function URL for the unqualified alias ($LATEST)."
}

variable "authorization_type" {
  type        = string
  default     = "NONE"
  description = "Authorization type for Function URL (NONE or AWS_IAM)."
}

variable "invoke_mode" {
  type        = string
  default     = null
  description = "Invoke mode for Function URL (BUFFERED or RESPONSE_STREAM)."
}

variable "cors" {
  type        = map(any) # More specific object type is ideal here
  default     = {}
  description = "CORS configuration for Function URL."
}

variable "recursive_loop" {
  type        = string
  default     = "Block"
  description = "Recursive loop detection setting (Allow/Block)."
  validation {
    condition     = contains(["Allow", "Block"], var.recursive_loop)
    error_message = "Recursive loop must be 'Allow' or 'Block'."
  }
}

variable "create_sam_metadata" {
  type        = bool
  default     = false
  description = "Whether to create SAM CLI metadata for local testing."
}

variable "source_path" {
  type        = string
  default     = null
  description = "Source path for SAM CLI metadata (pointing to your Lambda code directory)."
}

# The AWS region where resources will be deployed.
# This variable is distinct from the `region` in `naming_module_outputs`
# which is used for generating the resource names.
variable "region" {
  type        = string
  description = "The AWS region where these resources will be created."
}


# --- Data Sources ---
data "aws_partition" "current" {}
data "aws_region" "current" {}
data "aws_caller_identity" "current" {}
data "external" "archive_prepare" {
  # Add this if you intend to use an external data source to prepare archives.
  # This typically involves running a local script to zip your code.
  # If you manually create zips or use S3 directly, you might not need this.
  count = var.create && var.create_package && !var.store_on_s3 && var.local_existing_package == null ? 1 : 0
  program = ["bash", "-c", "echo '{\"filename\": \"/path/to/your/generated.zip\", \"was_missing\": false}'"] # REPLACE with actual archive command
  # Example: program = ["python", "${path.module}/scripts/archive_code.py", var.source_path]
  # Or use the `archive_file` data source for pure Terraform zipping.
}
# data "archive_file" "lambda_zip" {
#   count = var.create && var.create_package && !var.store_on_s3 && var.local_existing_package == null ? 1 : 0
#   type        = "zip"
#   source_dir  = var.source_path # e.g. path.module/src
#   output_path = "${path.module}/temp/lambda.zip"
# }


# --- Locals ---
locals {
  create = var.create && var.putin_khuylo

  # Original logic for archive filename handling, assuming data.external.archive_prepare
  archive_filename        = try(data.external.archive_prepare[0].result.filename, null)
  archive_filename_string = local.archive_filename != null ? local.archive_filename : ""
  archive_was_missing     = try(data.external.archive_prepare[0].result.was_missing, false)

  # Use a generated filename to determine when the source code has changed.
  # filename - to get package from local
  filename    = var.local_existing_package != null ? var.local_existing_package : (var.store_on_s3 ? null : local.archive_filename)
  was_missing = var.local_existing_package != null ? !fileexists(var.local_existing_package) : local.archive_was_missing

  # s3_* - to get package from S3
  s3_bucket         = var.s3_existing_package != null ? try(var.s3_existing_package.bucket, null) : (var.store_on_s3 ? var.s3_bucket : null)
  s3_key            = var.s3_existing_package != null ? try(var.s3_existing_package.key, null) : (var.store_on_s3 ? var.s3_prefix != null ? format("%s%s", var.s3_prefix, replace(local.archive_filename_string, "/^.*//", "")) : replace(local.archive_filename_string, "/^\\.//", "") : null)
  s3_object_version = var.s3_existing_package != null ? try(var.s3_existing_package.version_id, null) : (var.store_on_s3 ? try(aws_s3_object.lambda_package[0].version_id, null) : null)
}

# --- Resources ---

# You would typically define an IAM role here if `create_role` is true
# For example:
# resource "aws_iam_role" "lambda" {
#   count = local.create && var.create_role ? 1 : 0
#   name = var.naming_module_outputs.name # Or use var.naming_module_outputs.iro_name if you had a separate IAM role naming convention
#   assume_role_policy = jsonencode({
#     Version = "2012-10-17"
#     Statement = [
#       {
#         Action = "sts:AssumeRole"
#         Effect = "Allow"
#         Principal = {
#           Service = "lambda.amazonaws.com"
#         }
#       }
#     ]
#   })
#   tags = var.naming_module_outputs.tags
# }
#
# Placeholder for aws_iam_role.lambda - ensure this resource is defined elsewhere or create it here.
# For demonstration, assuming `aws_iam_role.lambda` exists if `var.create_role` is true.

resource "aws_lambda_function" "this" {
  count = local.create && var.create_function && !var.create_layer ? 1 : 0

  region = var.region # The AWS region to deploy in

  function_name              = var.naming_module_outputs.name # Apply generated name
  description                = var.description
  role                       = var.create_role ? aws_iam_role.lambda[0].arn : var.lambda_role
  handler                    = var.package_type != "Zip" ? null : var.handler
  memory_size                = var.memory_size
  reserved_concurrent_executions = var.reserved_concurrent_executions
  runtime                    = var.package_type != "Zip" ? null : var.runtime
  layers                     = var.layers
  timeout                    = var.lambda_at_edge ? min(var.timeout, 30) : var.timeout
  publish                    = (var.lambda_at_edge || var.snap_start) ? true : var.publish
  kms_key_arn                = var.kms_key_arn
  image_uri                  = var.image_uri
  package_type               = var.package_type
  architectures              = var.architectures
  code_signing_config_arn    = var.code_signing_config_arn
  replace_security_groups_on_destroy = var.replace_security_groups_on_destroy
  replacement_security_group_ids = var.replacement_security_group_ids
  skip_destroy               = var.skip_destroy

  /* ephemeral_storage is not supported in gov-cloud region, so it should be set to `null` */
  dynamic "ephemeral_storage" {
    for_each = var.ephemeral_storage_size == null ? [] : [true]

    content {
      size = var.ephemeral_storage_size
    }
  }

  filename         = local.filename
  source_code_hash = var.ignore_source_code_hash ? null : (local.filename == null ? false : fileexists(local.filename)) && !local.was_missing ? filebase64sha256(local.filename) : null

  s3_bucket         = local.s3_bucket
  s3_key            = local.s3_key
  s3_object_version = local.s3_object_version

  dynamic "image_config" {
    for_each = length(var.image_config_entry_point) > 0 || length(var.image_config_command) > 0 || var.image_config_working_directory != null ? [true] : []
    content {
      entry_point       = var.image_config_entry_point
      command           = var.image_config_command
      working_directory = var.image_config_working_directory
    }
  }

  dynamic "environment" {
    for_each = length(keys(var.environment_variables)) == 0 ? [] : [true]
    content {
      variables = var.environment_variables
    }
  }

  dynamic "dead_letter_config" {
    for_each = var.dead_letter_target_arn == null ? [] : [true]
    content {
      target_arn = var.dead_letter_target_arn
    }
  }

  dynamic "tracing_config" {
    for_each = var.tracing_mode == null ? [] : [true]
    content {
      mode = var.tracing_mode
    }
  }

  dynamic "vpc_config" {
    for_each = var.vpc_subnet_ids != null && var.vpc_security_group_ids != null ? [true] : []
    content {
      security_group_ids  = var.vpc_security_group_ids
      subnet_ids          = var.vpc_subnet_ids
      ipv6_allowed_for_dual_stack = var.ipv6_allowed_for_dual_stack
    }
  }

  dynamic "file_system_config" {
    for_each = var.file_system_arn != null && var.file_system_local_mount_path != null ? [true] : []
    content {
      local_mount_path = var.file_system_local_mount_path
      arn              = var.file_system_arn
    }
  }

  dynamic "snap_start" {
    for_each = var.snap_start ? [true] : []

    content {
      apply_on = "PublishedVersions"
    }
  }

  dynamic "logging_config" {
    # Dont create logging config on gov cloud as it is not avaible.
    # See https://github.com/hashicorp/terraform-provider-aws/issues/34810
    for_each = data.aws_partition.current.partition == "aws" ? [true] : []

    content {
      log_group           = coalesce(var.logging_log_group, "/aws/lambda/${var.lambda_at_edge ? "us-east-1." : ""}${var.naming_module_outputs.name}") # Use generated name
      log_format          = var.logging_log_format
      application_log_level = var.logging_log_format == "Text" ? null : var.logging_application_log_level
      system_log_level    = var.logging_log_format == "Text" ? null : var.logging_system_log_level
    }
  }

  dynamic "timeouts" {
    for_each = length(var.timeouts) > 0 ? [true] : []

    content {
      create = try(var.timeouts.create, null)
      update = try(var.timeouts.update, null)
      delete = try(var.timeouts.delete, null)
    }
  }

  # Apply generated tags, merging with any function-specific tags
  tags = merge(
    var.naming_module_outputs.tags,
    var.function_tags
  )

  # Add custom dependencies here if needed (e.g., specific IAM policies)
  depends_on = [
    # null_resource.archive, # Assumes 'archive_prepare' or equivalent handles local zip
    # aws_s3_object.lambda_package, # If you store on S3
    # aws_cloudwatch_log_group.lambda, # Ensure log group is created first
    # aws_iam_role.lambda, # Ensure IAM role is created first
    # Other IAM role policies/attachments as needed
  ]
}

resource "aws_lambda_layer_version" "this" {
  count = local.create && var.create_layer ? 1 : 0

  region = var.region

  layer_name               = coalesce(var.layer_name, var.naming_module_outputs.name) # Use generated name or explicit layer_name
  description              = var.description
  license_info             = var.license_info

  compatible_runtimes      = length(var.compatible_runtimes) > 0 ? var.compatible_runtimes : (var.runtime == "" ? null : [var.runtime])
  compatible_architectures = var.compatible_architectures
  skip_destroy             = var.layer_skip_destroy

  filename         = local.filename
  source_code_hash = var.ignore_source_code_hash ? null : (local.filename == null ? false : fileexists(local.filename)) && !local.was_missing ? filebase64sha256(local.filename) : null

  s3_bucket         = local.s3_bucket
  s3_key            = local.s3_key
  s3_object_version = local.s3_object_version

  tags = var.naming_module_outputs.tags # Apply generated tags

  depends_on = [
    # null_resource.archive, # Assumes 'archive_prepare' or equivalent handles local zip
    # aws_s3_object.lambda_package # If you store on S3
  ]
}

resource "aws_s3_object" "lambda_package" {
  count = local.create && var.store_on_s3 && var.create_package ? 1 : 0

  region = var.region

  bucket        = local.s3_bucket
  acl           = var.s3_acl
  key           = local.s3_key
  source        = data.external.archive_prepare[0].result.filename # Or use data.archive_file.lambda_zip[0].output_path
  storage_class = var.s3_object_storage_class

  server_side_encryption = var.s3_server_side_encryption
  kms_key_id             = var.s3_kms_key_id

  tags = merge(var.naming_module_outputs.tags, var.s3_object_tags) # Apply generated tags, merged with specific S3 tags

  dynamic "override_provider" {
    for_each = var.s3_object_override_default_tags ? [true] : []

    content {
      default_tags {
        tags = {}
      }
    }
  }

  depends_on = [
    data.external.archive_prepare # If using external for zip, ensure it runs first
    # data.archive_file.lambda_zip # If using archive_file for zip
  ]
}

# Data source to refer to an *existing* CloudWatch Log Group
data "aws_cloudwatch_log_group" "lambda" {
  count = local.create && var.create_function && !var.create_layer && var.use_existing_cloudwatch_log_group ? 1 : 0

  region = var.region

  name = coalesce(var.logging_log_group, "/aws/lambda/${var.lambda_at_edge ? "us-east-1." : ""}${var.naming_module_outputs.name}")
}

# Resource to *create* a new CloudWatch Log Group
resource "aws_cloudwatch_log_group" "lambda" {
  count = local.create && var.create_function && !var.create_layer && !var.use_existing_cloudwatch_log_group ? 1 : 0

  region = var.region

  name              = coalesce(var.logging_log_group, "/aws/lambda/${var.lambda_at_edge ? "us-east-1." : ""}${var.naming_module_outputs.name}") # Use generated name
  retention_in_days = var.cloudwatch_logs_retention_in_days
  kms_key_id        = var.cloudwatch_logs_kms_key_id
  skip_destroy      = var.cloudwatch_logs_skip_destroy
  log_group_class   = var.cloudwatch_logs_log_group_class

  tags = merge(var.naming_module_outputs.tags, var.cloudwatch_logs_tags) # Apply generated tags, merged with specific CW tags
}

resource "aws_lambda_provisioned_concurrency_config" "current_version" {
  count = local.create && var.create_function && !var.create_layer && var.provisioned_concurrent_executions > -1 ? 1 : 0

  region = var.region

  function_name = aws_lambda_function.this[0].function_name
  qualifier     = aws_lambda_function.this[0].version

  provisioned_concurrent_executions = var.provisioned_concurrent_executions
}

locals {
  qualifiers = zipmap(["current_version", "unqualified_alias"], [var.create_current_version_async_event_config ? true : null, var.create_unqualified_alias_async_event_config ? true : null])
}

resource "aws_lambda_function_event_invoke_config" "this" {
  for_each = { for k, v in local.qualifiers : k => v if v != null && local.create && var.create_function && !var.create_layer && var.create_async_event_config }

  region = var.region

  function_name = aws_lambda_function.this[0].function_name
  qualifier     = each.key == "current_version" ? aws_lambda_function.this[0].version : null

  maximum_event_age_in_seconds = var.maximum_event_age_in_seconds
  maximum_retry_attempts       = var.maximum_retry_attempts

  dynamic "destination_config" {
    for_each = var.destination_on_failure != null || var.destination_on_success != null ? [true] : []
    content {
      dynamic "on_failure" {
        for_each = var.destination_on_failure != null ? [true] : []
        content {
          destination = var.destination_on_failure
        }
      }

      dynamic "on_success" {
        for_each = var.destination_on_success != null ? [true] : []
        content {
          destination = var.destination_on_success
        }
      }
    }
  }
}

resource "aws_lambda_permission" "current_version_triggers" {
  for_each = { for k, v in var.allowed_triggers : k => v if local.create && var.create_function && !var.create_layer && var.create_current_version_allowed_triggers }

  region = var.region

  function_name = aws_lambda_function.this[0].function_name
  qualifier     = aws_lambda_function.this[0].version

  statement_id_prefix  = try(each.value.statement_id, each.key)
  action               = try(each.value.action, "lambda:InvokeFunction")
  principal            = try(each.value.principal, format("%s.amazonaws.com", try(each.value.service, "")))
  principal_org_id     = try(each.value.principal_org_id, null)
  source_arn           = try(each.value.source_arn, null)
  source_account       = try(each.value.source_account, null)
  event_source_token   = try(each.value.event_source_token, null)
  function_url_auth_type = try(each.value.function_url_auth_type, null)

  lifecycle {
    create_before_destroy = true
  }
}

# Error: Error adding new Lambda Permission for lambda: InvalidParameterValueException: We currently do not support adding policies for $LATEST.
resource "aws_lambda_permission" "unqualified_alias_triggers" {
  for_each = { for k, v in var.allowed_triggers : k => v if local.create && var.create_function && !var.create_layer && var.create_unqualified_alias_allowed_triggers }

  region = var.region

  function_name = aws_lambda_function.this[0].function_name

  statement_id_prefix  = try(each.value.statement_id, each.key)
  action               = try(each.value.action, "lambda:InvokeFunction")
  principal            = try(each.value.principal, format("%s.amazonaws.com", try(each.value.service, "")))
  principal_org_id     = try(each.value.principal_org_id, null)
  source_arn           = try(each.value.source_arn, null)
  source_account       = try(each.value.source_account, null)
  event_source_token   = try(each.value.event_source_token, null)
  function_url_auth_type = try(each.value.function_url_auth_type, null)

  lifecycle {
    create_before_destroy = true
  }
}

resource "aws_lambda_event_source_mapping" "this" {
  for_each = { for k, v in var.event_source_mapping : k => v if local.create && var.create_function && !var.create_layer && var.create_unqualified_alias_allowed_triggers }

  region = var.region

  function_name = aws_lambda_function.this[0].arn

  event_source_arn = try(each.value.event_source_arn, null)

  batch_size                         = try(each.value.batch_size, null)
  maximum_batching_window_in_seconds = try(each.value.maximum_batching_window_in_seconds, null)
  enabled                            = try(each.value.enabled, true)
  starting_position                  = try(each.value.starting_position, null)
  starting_position_timestamp        = try(each.value.starting_position_timestamp, null)
  parallelization_factor             = try(each.value.parallelization_factor, null)
  maximum_retry_attempts             = try(each.value.maximum_retry_attempts, null)
  maximum_record_age_in_seconds      = try(each.value.maximum_record_age_in_seconds, null)
  bisect_batch_on_function_error     = try(each.value.bisect_batch_on_function_error, null)
  topics                             = try(each.value.topics, null)
  queues                             = try(each.value.queues, null)
  function_response_types            = try(each.value.function_response_types, null)
  tumbling_window_in_seconds         = try(each.value.tumbling_window_in_seconds, null)

  dynamic "destination_config" {
    for_each = try(each.value.destination_arn_on_failure, null) != null ? [true] : []
    content {
      on_failure {
        destination_arn = each.value["destination_arn_on_failure"]
      }
    }
  }

  dynamic "scaling_config" {
    for_each = try([each.value.scaling_config], [])
    content {
      maximum_concurrency = try(scaling_config.value.maximum_concurrency, null)
    }
  }


  dynamic "self_managed_event_source" {
    for_each = try(each.value.self_managed_event_source, [])
    content {
      endpoints = self_managed_event_source.value.endpoints
    }
  }

  dynamic "self_managed_kafka_event_source_config" {
    for_each = try(each.value.self_managed_kafka_event_source_config, [])
    content {
      consumer_group_id = self_managed_kafka_event_source_config.value.consumer_group_id
    }
  }
  dynamic "amazon_managed_kafka_event_source_config" {
    for_each = try(each.value.amazon_managed_kafka_event_source_config, [])
    content {
      consumer_group_id = amazon_managed_kafka_event_source_config.value.consumer_group_id
    }
  }

  dynamic "source_access_configuration" {
    for_each = try(each.value.source_access_configuration, [])
    content {
      type = source_access_configuration.value["type"]
      uri  = source_access_configuration.value["uri"]
    }
  }

  dynamic "filter_criteria" {
    for_each = try(each.value.filter_criteria, null) != null ? [true] : []

    content {
      dynamic "filter" {
        for_each = try(flatten([each.value.filter_criteria]), [])

        content {
          pattern = try(filter.value.pattern, null)
        }
      }
    }
  }

  dynamic "document_db_event_source_config" {
    for_each = try(each.value.document_db_event_source_config, [])

    content {
      database_name  = document_db_event_source_config.value.database_name
      collection_name = try(document_db_event_source_config.value.collection_name, null)
      full_document  = try(document_db_event_source_config.value.full_document, null)
    }
  }

  dynamic "metrics_config" {
    for_each = try([each.value.metrics_config], [])

    content {
      metrics = metrics_config.value.metrics
    }
  }

  dynamic "provisioned_poller_config" {
    for_each = try([each.value.provisioned_poller_config], [])
    content {
      maximum_pollers = try(provisioned_poller_config.value.maximum_pollers, null)
      minimum_pollers = try(provisioned_poller_config.value.minimum_pollers, null)
    }
  }

  tags = var.naming_module_outputs.tags # Apply generated tags (or merge if specific ESM tags are needed)
}

resource "aws_lambda_function_url" "this" {
  count = local.create && var.create_function && !var.create_layer && var.create_lambda_function_url ? 1 : 0

  region = var.region

  function_name = aws_lambda_function.this[0].function_name

  # Error: error creating Lambda Function URL: ValidationException
  qualifier          = var.create_unqualified_alias_lambda_function_url ? null : aws_lambda_function.this[0].version
  authorization_type = var.authorization_type
  invoke_mode        = var.invoke_mode

  dynamic "cors" {
    for_each = length(keys(var.cors)) == 0 ? [] : [var.cors]

    content {
      allow_credentials = try(cors.value.allow_credentials, null)
      allow_headers     = try(cors.value.allow_headers, null)
      allow_methods     = try(cors.value.allow_methods, null)
      allow_origins     = try(cors.value.allow_origins, null)
      expose_headers    = try(cors.value.expose_headers, null)
      max_age           = try(cors.value.max_age, null)
    }
  }

  tags = var.naming_module_outputs.tags # Apply generated tags
}

resource "aws_lambda_function_recursion_config" "this" {
  count = local.create && var.create_function && !var.create_layer && var.recursive_loop == "Allow" ? 1 : 0

  region = var.region

  function_name  = aws_lambda_function.this[0].function_name
  recursive_loop = var.recursive_loop
}

# This resource contains the extra information required by SAM CLI to provide the testing capabilities
# to the TF application. The required data is where SAM CLI can find the Lambda function source code
# and what are the resources that contain the building logic.
resource "null_resource" "sam_metadata_aws_lambda_function" {
  count = local.create && var.create_sam_metadata && var.create_package && var.create_function && !var.create_layer ? 1 : 0

  triggers = {
    # This is a way to let SAM CLI correlates between the Lambda function resource, and this metadata
    # resource
    resource_name = "aws_lambda_function.this[0]"
    resource_type = "ZIP_LAMBDA_FUNCTION"

    # The Lambda function source code.
    original_source_code = jsonencode(var.source_path)

    # a property to let SAM CLI knows where to find the Lambda function source code if the provided
    # value for original_source_code attribute is map.
    source_code_property = "path"

    # A property to let SAM CLI knows where to find the Lambda function built output
    built_output_path = data.external.archive_prepare[0].result.filename
  }

  # SAM CLI can run terraform apply -target metadata resource, and this will apply the building
  # resources as well
  depends_on = [
    data.external.archive_prepare, # Ensure external data source (or archive_file) runs first
    # null_resource.archive # If you have a separate null_resource for archiving
  ]
}

# This resource contains the extra information required by SAM CLI to provide the testing capabilities
# to the TF application. The required data is where SAM CLI can find the Lambda layer source code
# and what are the resources that contain the building logic.
resource "null_resource" "sam_metadata_aws_lambda_layer_version" {
  count = local.create && var.create_sam_metadata && var.create_package && var.create_layer ? 1 : 0

  triggers = {
    # This is a way to let SAM CLI correlates between the Lambda layer resource, and this metadata
    # resource
    resource_name = "aws_lambda_layer_version.this[0]"
    resource_type = "LAMBDA_LAYER"

    # The Lambda layer source code.
    original_source_code = jsonencode(var.source_path)

    # a property to let SAM CLI knows where to find the Lambda layer source code if the provided
    # value for original_source_code attribute is map.
    source_code_property = "path"

    # A property to let SAM CLI knows where to find the Lambda layer built output
    built_output_path = data.external.archive_prepare[0].result.filename
  }

  # SAM CLI can run terraform apply -target metadata resource, and this will apply the building
  # resources as well
  depends_on = [
    data.external.archive_prepare, # Ensure external data source (or archive_file) runs first
    # null_resource.archive # If you have a separate null_resource for archiving
  ]
}

# --- Outputs for the Lambda Module ---
output "lambda_function_name" {
  description = "The name of the created Lambda function."
  value       = try(aws_lambda_function.this[0].function_name, null)
}

output "lambda_function_arn" {
  description = "The ARN of the created Lambda function."
  value       = try(aws_lambda_function.this[0].arn, null)
}

output "lambda_function_version" {
  description = "The version of the created Lambda function."
  value       = try(aws_lambda_function.this[0].version, null)
}

output "lambda_function_invoke_arn" {
  description = "The Invoke ARN of the created Lambda function."
  value       = try(aws_lambda_function.this[0].invoke_arn, null)
}

output "lambda_function_url" {
  description = "The URL of the created Lambda function URL."
  value       = try(aws_lambda_function_url.this[0].function_url, null)
}

output "lambda_layer_name" {
  description = "The name of the created Lambda layer."
  value       = try(aws_lambda_layer_version.this[0].layer_name, null)
}

output "lambda_layer_arn" {
  description = "The ARN of the created Lambda layer."
  value       = try(aws_lambda_layer_version.this[0].arn, null)
}

output "lambda_layer_version" {
  description = "The version of the created Lambda layer."
  value       = try(aws_lambda_layer_version.this[0].version, null)
}

output "cloudwatch_log_group_name" {
  description = "The name of the CloudWatch Log Group for the Lambda function."
  value       = try(aws_cloudwatch_log_group.lambda[0].name, data.aws_cloudwatch_log_group.lambda[0].name, null)
}





# terragrunt.hcl
# ... (your locals block and other common setup) ...

# Source for your custom lambda module
terraform {
  source = "../../modules/lambda" # Path to your actual lambda module
}

# Input variables for the lambda module
inputs = {
  # Naming convention modules (these would be defined elsewhere, e.g., parent terragrunt.hcl or a separate dependency)
  base_naming_module = {
    source = "../../common_modules_terraform/bright_naming_conventions"
    inputs = {
      app_group = local.project_app_group
      env       = local.env
      ledger    = local.project_ledger
      region    = local.region # Pass region here
      tier      = local.tier
      zone      = local.zone
    }
  }

  iro_lambda_naming_module = {
    source = "../../common_modules_terraform/bright_naming_conventions"
    inputs = {
      base_object = dependency.base_naming_module.outputs
      type        = "iro"
      purpose     = "lambda-execution"
    }
  }

  lmb_naming_module = {
    source = "../../common_modules_terraform/bright_naming_conventions"
    inputs = {
      base_object = dependency.base_naming_module.outputs
      type        = "lmb"
      purpose     = "my-service"
      instance    = "001"
    }
  }

  # Pass the outputs of the *specific* naming module relevant to this Lambda function
  # This is the key change for integrating your naming module
  naming_module_outputs = dependency.lmb_naming_module.outputs

  # Other Lambda specific variables (rest remain as they were)
  # Ensure the region variable for the module's provider configuration is also set if needed
  region          = local.region # This sets the provider region for the module
  filename        = "path/to/your/lambda.zip"
  source_code_hash = filebase64sha256("path/to/your/lambda.zip")
  handler         = "index.handler"
  memory_size     = 128
  runtime         = "nodejs18.x"
  timeout         = 30
  publish         = true
  log_retention   = local.log_retention
  aws_account_number_env = local.aws_account_number_env
  environment     = {
    VAR1 = "value1"
    VAR2 = "value2"
  }
  # ... other variables ...
}




# data blocks for current partition, region, caller identity (unchanged)
data "aws_partition" "current" {}
data "aws_region" "current" {}
data "aws_caller_identity" "current" {}

# New variable to accept outputs from your naming module
variable "naming_module_outputs" {
  description = "Outputs from the bright_naming_conventions module containing name, tags, etc."
  type = object({
    app_group  = string
    env        = string
    instance   = string
    ledger     = string
    log_prefix = string
    purpose    = string
    region     = string
    tier       = string
    type       = string
    zone       = string
    name       = string # This is the generated resource name
    tags       = map(string) # These are the generated tags
    log_path   = string
  })
}

# Existing variables from your Lambda module (unchanged unless explicitly modified for naming)
variable "create" {
  type        = bool
  description = "Whether to create the Lambda resource."
  default     = true
}

variable "putin_khuylo" { # Assuming this is a control variable from your context
  type        = bool
  description = "A control variable for resource creation."
  default     = true
}

variable "local_existing_package" {
  type        = string
  default     = null
  description = "Path to a local existing Lambda deployment package."
}

variable "store_on_s3" {
  type        = bool
  default     = false
  description = "Whether to store the Lambda package on S3."
}

variable "s3_bucket" {
  type        = string
  default     = null
  description = "S3 bucket for Lambda package storage."
}

variable "s3_prefix" {
  type        = string
  default     = null
  description = "S3 prefix for the Lambda package key."
}

variable "s3_existing_package" {
  type        = map(string)
  default     = null
  description = "Map containing details of an existing S3 package (bucket, key, version_id)."
}

variable "create_function" {
  type        = bool
  default     = true
  description = "Whether to create the Lambda function."
}

variable "create_layer" {
  type        = bool
  default     = false
  description = "Whether to create a Lambda layer."
}

variable "function_name" {
  type        = string
  default     = null # Will be overridden by naming_module_outputs.name
  description = "Name of the Lambda function (will be derived from naming_module_outputs.name)."
}

variable "description" {
  type        = string
  default     = "Managed by Terraform"
  description = "Description for the Lambda function or layer."
}

variable "create_role" {
  type        = bool
  default     = true
  description = "Whether to create the IAM role for Lambda."
}

variable "lambda_role" {
  type        = string
  default     = null # If create_role is false, this should be the ARN
  description = "ARN of an existing Lambda IAM role if not created by this module."
}

variable "handler" {
  type        = string
  default     = "index.handler"
  description = "Lambda handler (for Zip packages)."
}

variable "memory_size" {
  type        = number
  default     = 128
  description = "Memory size for the Lambda function."
}

variable "reserved_concurrent_executions" {
  type        = number
  default     = -1
  description = "Reserved concurrent executions for the Lambda function."
}

variable "runtime" {
  type        = string
  default     = "nodejs18.x"
  description = "Lambda runtime (for Zip packages)."
}

variable "layers" {
  type        = list(string)
  default     = []
  description = "List of Lambda layer ARNs."
}

variable "lambda_at_edge" {
  type        = bool
  default     = false
  description = "Whether this is a Lambda@Edge function."
}

variable "timeout" {
  type        = number
  default     = 3
  description = "Timeout for the Lambda function."
}

variable "publish" {
  type        = bool
  default     = false
  description = "Whether to publish a new version of the Lambda function."
}

variable "kms_key_arn" {
  type        = string
  default     = null
  description = "KMS Key ARN for Lambda environment variables encryption."
}

variable "image_uri" {
  type        = string
  default     = null
  description = "ECR image URI for container-based Lambda."
}

variable "package_type" {
  type        = string
  default     = "Zip"
  description = "Lambda package type (Zip or Image)."
}

variable "architectures" {
  type        = list(string)
  default     = ["x86_64"]
  description = "Lambda function architectures."
}

variable "code_signing_config_arn" {
  type        = string
  default     = null
  description = "Code Signing Configuration ARN for Lambda."
}

variable "replace_security_groups_on_destroy" {
  type        = bool
  default     = false
  description = "Whether to replace security groups on destroy."
}

variable "replacement_security_group_ids" {
  type        = list(string)
  default     = []
  description = "Replacement security group IDs for replace_security_groups_on_destroy."
}

variable "skip_destroy" {
  type        = bool
  default     = false
  description = "Whether to skip destroy for the Lambda function."
}

variable "ephemeral_storage_size" {
  type        = number
  default     = null
  description = "Ephemeral storage size for Lambda."
}

variable "ignore_source_code_hash" {
  type        = bool
  default     = false
  description = "Whether to ignore source code hash for updates."
}

variable "image_config_entry_point" {
  type        = list(string)
  default     = []
  description = "Entry point for image-based Lambda."
}

variable "image_config_command" {
  type        = list(string)
  default     = []
  description = "Command for image-based Lambda."
}

variable "image_config_working_directory" {
  type        = string
  default     = null
  description = "Working directory for image-based Lambda."
}

variable "environment_variables" {
  type        = map(string)
  default     = {}
  description = "Environment variables for the Lambda function."
}

variable "dead_letter_target_arn" {
  type        = string
  default     = null
  description = "Dead-letter queue/topic ARN."
}

variable "tracing_mode" {
  type        = string
  default     = null
  description = "Tracing mode for Lambda (e.g., Active, PassThrough)."
}

variable "vpc_subnet_ids" {
  type        = list(string)
  default     = null
  description = "Subnet IDs for VPC configuration."
}

variable "vpc_security_group_ids" {
  type        = list(string)
  default     = null
  description = "Security Group IDs for VPC configuration."
}

variable "ipv6_allowed_for_dual_stack" {
  type        = bool
  default     = false
  description = "Whether IPv6 is allowed for dual-stack VPC."
}

variable "file_system_arn" {
  type        = string
  default     = null
  description = "ARN of EFS file system."
}

variable "file_system_local_mount_path" {
  type        = string
  default     = null
  description = "Local mount path for EFS."
}

variable "snap_start" {
  type        = bool
  default     = false
  description = "Whether to enable SnapStart."
}

variable "logging_log_group" {
  type        = string
  default     = null # Will be derived from naming_module_outputs.log_path or name
  description = "Name of the CloudWatch log group."
}

variable "logging_log_format" {
  type        = string
  default     = "JSON"
  description = "Log format (JSON, Text)."
}

variable "logging_application_log_level" {
  type        = string
  default     = "INFO"
  description = "Application log level."
}

variable "logging_system_log_level" {
  type        = string
  default     = "INFO"
  description = "System log level."
}

variable "timeouts" {
  type        = map(string)
  default     = {}
  description = "Timeouts for Lambda resource operations."
}

variable "include_default_tag" {
  type        = bool
  default     = true
  description = "Whether to include default tags (terraform-aws-modules)."
}

variable "tags" {
  type        = map(string)
  default     = {}
  description = "Additional tags to apply to resources."
}

variable "function_tags" {
  type        = map(string)
  default     = {}
  description = "Tags specific to the Lambda function."
}

variable "layer_name" {
  type        = string
  default     = null # Will be overridden by naming_module_outputs.name
  description = "Name of the Lambda layer (will be derived from naming_module_outputs.name)."
}

variable "license_info" {
  type        = string
  default     = null
  description = "License information for the Lambda layer."
}

variable "compatible_runtimes" {
  type        = list(string)
  default     = []
  description = "Compatible runtimes for the Lambda layer."
}

variable "compatible_architectures" {
  type        = list(string)
  default     = []
  description = "Compatible architectures for the Lambda layer."
}

variable "layer_skip_destroy" {
  type        = bool
  default     = false
  description = "Whether to skip destroy for the Lambda layer."
}

variable "create_package" {
  type        = bool
  default     = true
  description = "Whether to create the Lambda package."
}

variable "s3_acl" {
  type        = string
  default     = "private"
  description = "ACL for the S3 object."
}

variable "s3_object_storage_class" {
  type        = string
  default     = "STANDARD"
  description = "Storage class for the S3 object."
}

variable "s3_server_side_encryption" {
  type        = string
  default     = "AES256"
  description = "Server-side encryption for S3 object."
}

variable "s3_kms_key_id" {
  type        = string
  default     = null
  description = "KMS Key ID for S3 object encryption."
}

variable "s3_object_tags_only" {
  type        = bool
  default     = false
  description = "Whether to apply only s3_object_tags."
}

variable "s3_object_tags" {
  type        = map(string)
  default     = {}
  description = "Tags specific to the S3 object."
}

variable "s3_object_override_default_tags" {
  type        = bool
  default     = false
  description = "Whether to override default tags for S3 object."
}

variable "use_existing_cloudwatch_log_group" {
  type        = bool
  default     = false
  description = "Whether to use an existing CloudWatch log group."
}

variable "cloudwatch_logs_retention_in_days" {
  type        = number
  default     = 30
  description = "CloudWatch logs retention in days."
}

variable "cloudwatch_logs_kms_key_id" {
  type        = string
  default     = null
  description = "KMS Key ID for CloudWatch logs."
}

variable "cloudwatch_logs_skip_destroy" {
  type        = bool
  default     = false
  description = "Whether to skip destroy for CloudWatch log group."
}

variable "cloudwatch_logs_log_group_class" {
  type        = string
  default     = "STANDARD"
  description = "Log group class for CloudWatch logs."
}

variable "cloudwatch_logs_tags" {
  type        = map(string)
  default     = {}
  description = "Tags specific to the CloudWatch log group."
}

variable "provisioned_concurrent_executions" {
  type        = number
  default     = -1
  description = "Provisioned concurrent executions."
}

variable "create_current_version_async_event_config" {
  type        = bool
  default     = false
  description = "Whether to create async event config for current version."
}

variable "create_unqualified_alias_async_event_config" {
  type        = bool
  default     = false
  description = "Whether to create async event config for unqualified alias."
}

variable "create_async_event_config" {
  type        = bool
  default     = false
  description = "Whether to create async event config."
}

variable "maximum_event_age_in_seconds" {
  type        = number
  default     = null
  description = "Maximum event age in seconds."
}

variable "maximum_retry_attempts" {
  type        = number
  default     = null
  description = "Maximum retry attempts."
}

variable "destination_on_failure" {
  type        = string
  default     = null
  description = "Destination ARN on failure."
}

variable "destination_on_success" {
  type        = string
  default     = null
  description = "Destination ARN on success."
}

variable "allowed_triggers" {
  type = map(object({
    statement_id         = optional(string)
    action               = optional(string)
    principal            = optional(string)
    principal_org_id     = optional(string)
    service              = optional(string) # Custom attribute to help build principal
    source_arn           = optional(string)
    source_account       = optional(string)
    event_source_token   = optional(string)
    function_url_auth_type = optional(string)
  }))
  default = {}
  description = "Map of allowed triggers for the Lambda function."
}

variable "create_current_version_allowed_triggers" {
  type        = bool
  default     = true
  description = "Whether to create allowed triggers for the current version."
}

variable "create_unqualified_alias_allowed_triggers" {
  type        = bool
  default     = false
  description = "Whether to create allowed triggers for unqualified alias."
}

variable "event_source_mapping" {
  type        = map(any)
  default     = {}
  description = "Map of event source mappings."
}

variable "create_lambda_function_url" {
  type        = bool
  default     = false
  description = "Whether to create a Lambda Function URL."
}

variable "create_unqualified_alias_lambda_function_url" {
  type        = bool
  default     = false
  description = "Whether to create a Function URL for the unqualified alias."
}

variable "authorization_type" {
  type        = string
  default     = "NONE"
  description = "Authorization type for Function URL."
}

variable "invoke_mode" {
  type        = string
  default     = null
  description = "Invoke mode for Function URL."
}

variable "cors" {
  type        = map(any)
  default     = {}
  description = "CORS configuration for Function URL."
}

variable "recursive_loop" {
  type        = string
  default     = "Block"
  description = "Recursive loop detection setting (Allow/Block)."
}

variable "create_sam_metadata" {
  type        = bool
  default     = false
  description = "Whether to create SAM CLI metadata."
}

variable "source_path" {
  type        = string
  default     = null
  description = "Source path for SAM CLI metadata."
}


locals {
  # Leverage the `create` variable from the calling module's outputs (if passed)
  # or default to var.create && var.putin_khuylo if not provided by naming_module_outputs
  create = var.create && var.putin_khuylo

  archive_filename        = try(data.external.archive_prepare[0].result.filename, null)
  archive_filename_string = local.archive_filename != null ? local.archive_filename : ""
  archive_was_missing     = try(data.external.archive_prepare[0].result.was_missing, false)

  # Use a generated filename to determine when the source code has changed.
  filename    = var.local_existing_package != null ? var.local_existing_package : (var.store_on_s3 ? null : local.archive_filename)
  was_missing = var.local_existing_package != null ? !fileexists(var.local_existing_package) : local.archive_was_missing

  # s3_* - to get package from S3
  s3_bucket         = var.s3_existing_package != null ? try(var.s3_existing_package.bucket, null) : (var.store_on_s3 ? var.s3_bucket : null)
  s3_key            = var.s3_existing_package != null ? try(var.s3_existing_package.key, null) : (var.store_on_s3 ? var.s3_prefix != null ? format("%s%s", var.s3_prefix, replace(local.archive_filename_string, "/^.*//", "")) : replace(local.archive_filename_string, "/^\\.//", "") : null)
  s3_object_version = var.s3_existing_package != null ? try(var.s3_existing_package.version_id, null) : (var.store_on_s3 ? try(aws_s3_object.lambda_package[0].version_id, null) : null)

}

resource "aws_lambda_function" "this" {
  # Use naming_module_outputs.name directly for function_name
  count = local.create && var.create_function && !var.create_layer ? 1 : 0

  region = var.region # This 'region' is the AWS region where the resource will be deployed.

  function_name              = var.naming_module_outputs.name # Use the generated name
  description                = var.description
  role                       = var.create_role ? aws_iam_role.lambda[0].arn : var.lambda_role
  handler                    = var.package_type != "Zip" ? null : var.handler
  memory_size                = var.memory_size
  reserved_concurrent_executions = var.reserved_concurrent_executions
  runtime                    = var.package_type != "Zip" ? null : var.runtime
  layers                     = var.layers
  timeout                    = var.lambda_at_edge ? min(var.timeout, 30) : var.timeout
  publish                    = (var.lambda_at_edge || var.snap_start) ? true : var.publish
  kms_key_arn                = var.kms_key_arn
  image_uri                  = var.image_uri
  package_type               = var.package_type
  architectures              = var.architectures
  code_signing_config_arn    = var.code_signing_config_arn
  replace_security_groups_on_destroy = var.replace_security_groups_on_destroy
  replacement_security_group_ids = var.replacement_security_group_ids
  skip_destroy               = var.skip_destroy

  /* ephemeral_storage is not supported in gov-cloud region, so it should be set to `null` */
  dynamic "ephemeral_storage" {
    for_each = var.ephemeral_storage_size == null ? [] : [true]

    content {
      size = var.ephemeral_storage_size
    }
  }

  filename         = local.filename
  source_code_hash = var.ignore_source_code_hash ? null : (local.filename == null ? false : fileexists(local.filename)) && !local.was_missing ? filebase64sha256(local.filename) : null

  s3_bucket         = local.s3_bucket
  s3_key            = local.s3_key
  s3_object_version = local.s3_object_version

  dynamic "image_config" {
    for_each = length(var.image_config_entry_point) > 0 || length(var.image_config_command) > 0 || var.image_config_working_directory != null ? [true] : []
    content {
      entry_point       = var.image_config_entry_point
      command           = var.image_config_command
      working_directory = var.image_config_working_directory
    }
  }

  dynamic "environment" {
    for_each = length(keys(var.environment_variables)) == 0 ? [] : [true]
    content {
      variables = var.environment_variables
    }
  }

  dynamic "dead_letter_config" {
    for_each = var.dead_letter_target_arn == null ? [] : [true]
    content {
      target_arn = var.dead_letter_target_arn
    }
  }

  dynamic "tracing_config" {
    for_each = var.tracing_mode == null ? [] : [true]
    content {
      mode = var.tracing_mode
    }
  }

  dynamic "vpc_config" {
    for_each = var.vpc_subnet_ids != null && var.vpc_security_group_ids != null ? [true] : []
    content {
      security_group_ids  = var.vpc_security_group_ids
      subnet_ids          = var.vpc_subnet_ids
      ipv6_allowed_for_dual_stack = var.ipv6_allowed_for_dual_stack
    }
  }

  dynamic "file_system_config" {
    for_each = var.file_system_arn != null && var.file_system_local_mount_path != null ? [true] : []
    content {
      local_mount_path = var.file_system_local_mount_path
      arn              = var.file_system_arn
    }
  }

  dynamic "snap_start" {
    for_each = var.snap_start ? [true] : []

    content {
      apply_on = "PublishedVersions"
    }
  }

  dynamic "logging_config" {
    # Dont create logging config on gov cloud as it is not avaible.
    # See https://github.com/hashicorp/terraform-provider-aws/issues/34810
    for_each = data.aws_partition.current.partition == "aws" ? [true] : []

    content {
      log_group           = coalesce(var.logging_log_group, "/aws/lambda/${var.naming_module_outputs.name}") # Use generated name here
      log_format          = var.logging_log_format
      application_log_level = var.logging_log_format == "Text" ? null : var.logging_application_log_level
      system_log_level    = var.logging_log_format == "Text" ? null : var.logging_system_log_level
    }
  }

  dynamic "timeouts" {
    for_each = length(var.timeouts) > 0 ? [true] : []

    content {
      create = try(var.timeouts.create, null)
      update = try(var.timeouts.update, null)
      delete = try(var.timeouts.delete, null)
    }
  }

  tags = var.naming_module_outputs.tags # Apply generated tags
}

resource "aws_lambda_layer_version" "this" {
  count = local.create && var.create_layer ? 1 : 0

  region = var.region

  layer_name               = var.naming_module_outputs.name # Use the generated name
  description              = var.description
  license_info             = var.license_info

  compatible_runtimes      = length(var.compatible_runtimes) > 0 ? var.compatible_runtimes : (var.runtime == "" ? null : [var.runtime])
  compatible_architectures = var.compatible_architectures
  skip_destroy             = var.layer_skip_destroy

  filename         = local.filename
  source_code_hash = var.ignore_source_code_hash ? null : (local.filename == null ? false : fileexists(local.filename)) && !local.was_missing ? filebase64sha256(local.filename) : null

  s3_bucket         = local.s3_bucket
  s3_key            = local.s3_key
  s3_object_version = local.s3_object_version

  tags = var.naming_module_outputs.tags # Apply generated tags

  depends_on = [null_resource.archive, aws_s3_object.lambda_package]
}

resource "aws_s3_object" "lambda_package" {
  count = local.create && var.store_on_s3 && var.create_package ? 1 : 0

  region = var.region

  bucket        = local.s3_bucket
  acl           = var.s3_acl
  key           = local.s3_key
  source        = data.external.archive_prepare[0].result.filename
  storage_class = var.s3_object_storage_class

  server_side_encryption = var.s3_server_side_encryption
  kms_key_id             = var.s3_kms_key_id

  # Merge specific S3 object tags with the generated tags
  tags = merge(
    var.naming_module_outputs.tags,
    var.s3_object_tags
  )

  dynamic "override_provider" {
    for_each = var.s3_object_override_default_tags ? [true] : []

    content {
      default_tags {
        tags = {}
      }
    }
  }

  depends_on = [null_resource.archive]
}

data "aws_cloudwatch_log_group" "lambda" {
  count = local.create && var.create_function && !var.create_layer && var.use_existing_cloudwatch_log_group ? 1 : 0

  region = var.region

  # Use the generated name for consistency
  name = coalesce(var.logging_log_group, "/aws/lambda/${var.lambda_at_edge ? "us-east-1." : ""}${var.naming_module_outputs.name}")
}

resource "aws_cloudwatch_log_group" "lambda" {
  count = local.create && var.create_function && !var.create_layer && !var.use_existing_cloudwatch_log_group ? 1 : 0

  region = var.region

  # Use the generated name for consistency
  name              = coalesce(var.logging_log_group, "/aws/lambda/${var.lambda_at_edge ? "us-east-1." : ""}${var.naming_module_outputs.name}")
  retention_in_days = var.cloudwatch_logs_retention_in_days
  kms_key_id        = var.cloudwatch_logs_kms_key_id
  skip_destroy      = var.cloudwatch_logs_skip_destroy
  log_group_class   = var.cloudwatch_logs_log_group_class

  tags = var.naming_module_outputs.tags # Apply generated tags
}

resource "aws_lambda_provisioned_concurrency_config" "current_version" {
  count = local.create && var.create_function && !var.create_layer && var.provisioned_concurrent_executions > -1 ? 1 : 0

  region = var.region

  function_name = aws_lambda_function.this[0].function_name
  qualifier     = aws_lambda_function.this[0].version

  provisioned_concurrent_executions = var.provisioned_concurrent_executions
}

locals {
  qualifiers = zipmap(["current_version", "unqualified_alias"], [var.create_current_version_async_event_config ? true : null, var.create_unqualified_alias_async_event_config ? true : null])
}

resource "aws_lambda_function_event_invoke_config" "this" {
  for_each = { for k, v in local.qualifiers : k => v if v != null && local.create && var.create_function && !var.create_layer && var.create_async_event_config }

  region = var.region

  function_name = aws_lambda_function.this[0].function_name
  qualifier     = each.key == "current_version" ? aws_lambda_function.this[0].version : null

  maximum_event_age_in_seconds = var.maximum_event_age_in_seconds
  maximum_retry_attempts       = var.maximum_retry_attempts

  dynamic "destination_config" {
    for_each = var.destination_on_failure != null || var.destination_on_success != null ? [true] : []
    content {
      dynamic "on_failure" {
        for_each = var.destination_on_failure != null ? [true] : []
        content {
          destination = var.destination_on_failure
        }
      }

      dynamic "on_success" {
        for_each = var.destination_on_success != null ? [true] : []
        content {
          destination = var.destination_on_success
        }
      }
    }
  }
}

resource "aws_lambda_permission" "current_version_triggers" {
  for_each = { for k, v in var.allowed_triggers : k => v if local.create && var.create_function && !var.create_layer && var.create_current_version_allowed_triggers }

  region = var.region

  function_name = aws_lambda_function.this[0].function_name
  qualifier     = aws_lambda_function.this[0].version

  statement_id_prefix  = try(each.value.statement_id, each.key)
  action               = try(each.value.action, "lambda:InvokeFunction")
  principal            = try(each.value.principal, format("%s.amazonaws.com", try(each.value.service, "")))
  principal_org_id     = try(each.value.principal_org_id, null)
  source_arn           = try(each.value.source_arn, null)
  source_account       = try(each.value.source_account, null)
  event_source_token   = try(each.value.event_source_token, null)
  function_url_auth_type = try(each.value.function_url_auth_type, null)

  lifecycle {
    create_before_destroy = true
  }
}

# Error: Error adding new Lambda Permission for lambda: InvalidParameterValueException: We currently do not support adding policies for $LATEST.
resource "aws_lambda_permission" "unqualified_alias_triggers" {
  for_each = { for k, v in var.allowed_triggers : k => v if local.create && var.create_function && !var.create_layer && var.create_unqualified_alias_allowed_triggers }

  region = var.region

  function_name = aws_lambda_function.this[0].function_name

  statement_id_prefix  = try(each.value.statement_id, each.key)
  action               = try(each.value.action, "lambda:InvokeFunction")
  principal            = try(each.value.principal, format("%s.amazonaws.com", try(each.value.service, "")))
  principal_org_id     = try(each.value.principal_org_id, null)
  source_arn           = try(each.value.source_arn, null)
  source_account       = try(each.value.source_account, null)
  event_source_token   = try(each.value.event_source_token, null)
  function_url_auth_type = try(each.value.function_url_auth_type, null)

  lifecycle {
    create_before_destroy = true
  }
}

resource "aws_lambda_event_source_mapping" "this" {
  for_each = { for k, v in var.event_source_mapping : k => v if local.create && var.create_function && !var.create_layer && var.create_unqualified_alias_allowed_triggers }

  region = var.region

  function_name = aws_lambda_function.this[0].arn

  event_source_arn = try(each.value.event_source_arn, null)

  batch_size                         = try(each.value.batch_size, null)
  maximum_batching_window_in_seconds = try(each.value.maximum_batching_window_in_seconds, null)
  enabled                            = try(each.value.enabled, true)
  starting_position                  = try(each.value.starting_position, null)
  starting_position_timestamp        = try(each.value.starting_position_timestamp, null)
  parallelization_factor             = try(each.value.parallelization_factor, null)
  maximum_retry_attempts             = try(each.value.maximum_retry_attempts, null)
  maximum_record_age_in_seconds      = try(each.value.maximum_record_age_in_seconds, null)
  bisect_batch_on_function_error     = try(each.value.bisect_batch_on_function_error, null)
  topics                             = try(each.value.topics, null)
  queues                             = try(each.value.queues, null)
  function_response_types            = try(each.value.function_response_types, null)
  tumbling_window_in_seconds         = try(each.value.tumbling_window_in_seconds, null)

  dynamic "destination_config" {
    for_each = try(each.value.destination_arn_on_failure, null) != null ? [true] : []
    content {
      on_failure {
        destination_arn = each.value["destination_arn_on_failure"]
      }
    }
  }

  dynamic "scaling_config" {
    for_each = try([each.value.scaling_config], [])
    content {
      maximum_concurrency = try(scaling_config.value.maximum_concurrency, null)
    }
  }


  dynamic "self_managed_event_source" {
    for_each = try(each.value.self_managed_event_source, [])
    content {
      endpoints = self_managed_event_source.value.endpoints
    }
  }

  dynamic "self_managed_kafka_event_source_config" {
    for_each = try(each.value.self_managed_kafka_event_source_config, [])
    content {
      consumer_group_id = self_managed_kafka_event_source_config.value.consumer_group_id
    }
  }
  dynamic "amazon_managed_kafka_event_source_config" {
    for_each = try(each.value.amazon_managed_kafka_event_source_config, [])
    content {
      consumer_group_id = amazon_managed_kafka_event_source_config.value.consumer_group_id
    }
  }

  dynamic "source_access_configuration" {
    for_each = try(each.value.source_access_configuration, [])
    content {
      type = source_access_configuration.value["type"]
      uri  = source_access_configuration.value["uri"]
    }
  }

  dynamic "filter_criteria" {
    for_each = try(each.value.filter_criteria, null) != null ? [true] : []

    content {
      dynamic "filter" {
        for_each = try(flatten([each.value.filter_criteria]), [])

        content {
          pattern = try(filter.value.pattern, null)
        }
      }
    }
  }

  dynamic "document_db_event_source_config" {
    for_each = try(each.value.document_db_event_source_config, [])

    content {
      database_name  = document_db_event_source_config.value.database_name
      collection_name = try(document_db_event_source_config.value.collection_name, null)
      full_document  = try(document_db_event_source_config.value.full_document, null)
    }
  }

  dynamic "metrics_config" {
    for_each = try([each.value.metrics_config], [])

    content {
      metrics = metrics_config.value.metrics
    }
  }

  dynamic "provisioned_poller_config" {
    for_each = try([each.value.provisioned_poller_config], [])
    content {
      maximum_pollers = try(provisioned_poller_config.value.maximum_pollers, null)
      minimum_pollers = try(provisioned_poller_config.value.minimum_pollers, null)
    }
  }

  tags = var.naming_module_outputs.tags # Apply generated tags (or merge if specific ESM tags are needed)
}

resource "aws_lambda_function_url" "this" {
  count = local.create && var.create_function && !var.create_layer && var.create_lambda_function_url ? 1 : 0

  region = var.region

  function_name = aws_lambda_function.this[0].function_name

  # Error: error creating Lambda Function URL: ValidationException
  qualifier          = var.create_unqualified_alias_lambda_function_url ? null : aws_lambda_function.this[0].version
  authorization_type = var.authorization_type
  invoke_mode        = var.invoke_mode

  dynamic "cors" {
    for_each = length(keys(var.cors)) == 0 ? [] : [var.cors]

    content {
      allow_credentials = try(cors.value.allow_credentials, null)
      allow_headers     = try(cors.value.allow_headers, null)
      allow_methods     = try(cors.value.allow_methods, null)
      allow_origins     = try(cors.value.allow_origins, null)
      expose_headers    = try(cors.value.expose_headers, null)
      max_age           = try(cors.value.max_age, null)
    }
  }

  tags = var.naming_module_outputs.tags # Apply generated tags
}

resource "aws_lambda_function_recursion_config" "this" {
  count = local.create && var.create_function && !var.create_layer && var.recursive_loop == "Allow" ? 1 : 0

  region = var.region

  function_name  = aws_lambda_function.this[0].function_name
  recursive_loop = var.recursive_loop
}

# This resource contains the extra information required by SAM CLI to provide the testing capabilities
# to the TF application. The required data is where SAM CLI can find the Lambda function source code
# and what are the resources that contain the building logic.
resource "null_resource" "sam_metadata_aws_lambda_function" {
  count = local.create && var.create_sam_metadata && var.create_package && var.create_function && !var.create_layer ? 1 : 0

  triggers = {
    # This is a way to let SAM CLI correlates between the Lambda function resource, and this metadata
    # resource
    resource_name = "aws_lambda_function.this[0]"
    resource_type = "ZIP_LAMBDA_FUNCTION"

    # The Lambda function source code.
    original_source_code = jsonencode(var.source_path)

    # a property to let SAM CLI knows where to find the Lambda function source code if the provided
    # value for original_source_code attribute is map.
    source_code_property = "path"

    # A property to let SAM CLI knows where to find the Lambda function built output
    built_output_path = data.external.archive_prepare[0].result.filename
  }

  # SAM CLI can run terraform apply -target metadata resource, and this will apply the building
  # resources as well
  depends_on = [data.external.archive_prepare, null_resource.archive]
}

# This resource contains the extra information required by SAM CLI to provide the testing capabilities
# to the TF application. The required data is where SAM CLI can find the Lambda layer source code
# and what are the resources that contain the building logic.
resource "null_resource" "sam_metadata_aws_lambda_layer_version" {
  count = local.create && var.create_sam_metadata && var.create_package && var.create_layer ? 1 : 0

  triggers = {
    # This is a way to let SAM CLI correlates between the Lambda layer resource, and this metadata
    # resource
    resource_name = "aws_lambda_layer_version.this[0]"
    resource_type = "LAMBDA_LAYER"

    # The Lambda layer source code.
    original_source_code = jsonencode(var.source_path)

    # a property to let SAM CLI knows where to find the Lambda layer source code if the provided
    # value for original_source_code attribute is map.
    source_code_property = "path"

    # A property to let SAM CLI knows where to find the Lambda layer built output
    built_output_path = data.external.archive_prepare[0].result.filename
  }

  # SAM CLI can run terraform apply -target metadata resource, and this will apply the building
  # resources as well
  depends_on = [data.external.archive_prepare, null_resource.archive]
}

# Add outputs if they don't already exist in your original module
output "lambda_function_name" {
  description = "The name of the created Lambda function."
  value       = try(aws_lambda_function.this[0].function_name, null)
}

output "lambda_function_arn" {
  description = "The ARN of the created Lambda function."
  value       = try(aws_lambda_function.this[0].arn, null)
}

output "lambda_layer_name" {
  description = "The name of the created Lambda layer."
  value       = try(aws_lambda_layer_version.this[0].layer_name, null)
}

output "lambda_layer_arn" {
  description = "The ARN of the created Lambda layer."
  value       = try(aws_lambda_layer_version.this[0].arn, null)
}



# common_modules_terraform/bright_naming_conventions/main.tf

variable "base_object" {
  description = "A base object from which to inherit naming components (e.g., from another naming module)."
  type        = any
  default     = null
}

variable "app_group" {
  description = "The application group."
  type        = string
  default     = ""
}

variable "env" {
  description = "The environment (e.g., dev, qa, prod)."
  type        = string
  default     = ""
}

variable "instance" {
  description = "An optional instance identifier for resources that may have multiple instances."
  type        = string
  default     = ""
}

variable "ledger" {
  description = "The ledger or cost center for the resource."
  type        = string
  default     = ""
}

variable "log_prefix" {
  description = "The base log prefix for S3 logging. Defaults to 'log/'. Set to empty string to inherit."
  type        = string
  default     = "log/" # Default for this module if no base_object and no explicit var.log_prefix
}

variable "purpose" {
  description = "The specific purpose of the resource within the application group."
  type        = string
  default     = ""
}

variable "region" { # Renamed from 'site'
  description = "The AWS region abbreviation (e.g., 'ue1' for us-east-1, 'uw2' for us-west-2)."
  type        = string
  default     = ""
}

variable "tier" {
  description = "The application tier (e.g., 'web', 'api', 'data', 'batch', 'security')." # More expressive
  type        = string
  default     = ""
}

variable "type" {
  description = "The AWS resource type abbreviation (e.g., 'lmb' for Lambda, 's3b' for S3 Bucket)."
  type        = string
  default     = ""
}

variable "zone" {
  description = "The availability zone (e.g., 'use1a'). Used for tagging and for inherently zone-specific resource names."
  type        = string
  default     = "z1" # Default for general purpose, actual AZ for specific resources
}

variable "additional_tags" {
  description = "Additional tags to merge with the default tag set."
  type        = map(string)
  default     = {}
}


locals {
  // Determine values for inherited values using try() for cleaner syntax
  base_app_group  = try(var.base_object.app_group, "")
  base_env        = try(var.base_object.env, "")
  base_instance   = try(var.base_object.instance, "")
  base_ledger     = try(var.base_object.ledger, "")
  base_log_prefix = try(var.base_object.log_prefix, "log/")
  base_purpose    = try(var.base_object.purpose, "")
  base_region     = try(var.base_object.region, "") # Renamed from base_site
  base_tier       = try(var.base_object.tier, "")
  base_type       = try(var.base_object.type, "")
  base_zone       = try(var.base_object.zone, "z1")

  // Use provided values over inherited values (empty string means "not provided here, check base")
  app_group  = var.app_group != "" ? var.app_group : local.base_app_group
  env        = var.env != "" ? var.env : local.base_env
  instance   = var.instance != "" ? var.instance : local.base_instance
  ledger     = var.ledger != "" ? var.ledger : local.base_ledger
  log_prefix = var.log_prefix != "" && var.log_prefix != "log/" ? var.log_prefix : local.base_log_prefix
  purpose    = var.purpose != "" ? var.purpose : local.base_purpose
  region     = var.region != "" ? var.region : local.base_region # Renamed from site
  tier       = var.tier != "" ? var.tier : local.base_tier
  type       = var.type != "" ? var.type : local.base_type
  zone       = var.zone != "" ? var.zone : local.base_zone


  // Entity Name map
  //  Removed 'zone' from most names, kept for inherently zone-specific resources.
  //  Filtered to only include requested services.
  aws_names = {
    // AutoScaling
    asg = lower(join("", [local.region, local.env, "asg", local.tier, local.purpose, local.instance]))
    asc = lower(join("", [local.region, local.env, "asc", local.tier, local.purpose, local.instance]))
    asp = lower(join("", [local.region, local.env, "asp", local.tier, local.purpose, local.instance]))

    // Container service
    ecc = lower(join("", [local.region, local.env, "ecc", local.tier, local.purpose, local.instance]))
    ecr = lower(join("", [local.region, local.env, "ecr", local.tier, local.purpose, local.instance]))
    ecs = lower(join("", [local.region, local.env, "ecs", local.tier, local.purpose, local.instance]))
    ect = lower(join("", [local.region, local.env, "ect", local.tier, local.purpose, local.instance]))

    //Dynamo DB
    dyg = lower(join("", [local.region, local.env, "dut", local.tier, local.purpose, local.instance]))
    dyi = lower(join("", [local.region, local.env, "dyi", local.tier, local.purpose, local.instance]))
    dyt = lower(join("", [local.region, local.env, "dyt", local.tier, local.purpose, local.instance]))

    // ec2
    ami = lower(join("", [local.region, local.env, "ami", local.tier, local.purpose, local.instance]))
    ebs = lower(join("", [local.region, local.env, "ebs", local.tier, local.purpose, local.instance]))
    ebv = lower(join("", [local.region, local.env, "ebv", local.tier, local.purpose, local.instance]))
    ec2 = lower(join("", [local.region, local.env, local.tier, local.purpose, local.instance])) // Zone implicit
    eip = lower(join("", [local.region, local.env, local.tier, local.purpose, local.instance])) // Zone implicit
    int = lower(join("", [local.region, local.env, local.zone, "int", local.tier, local.purpose, local.instance])) // Zone explicit
    skp = lower(join("", [local.region, local.env, "skp", local.tier, local.purpose, local.instance]))
    sgp = lower(join("", [local.region, local.env, "sgp", local.tier, local.purpose, local.instance]))

    // EC2 Load Balancing
    alb = lower(join("", [local.region, local.env, "alb", local.tier, local.purpose, local.instance]))
    nlb = lower(join("", [local.region, local.env, local.zone, "nlb", local.tier, local.purpose, local.instance])) // Zone explicit
    lbl = lower(join("", [local.region, local.env, "lbl", local.tier, local.purpose, local.instance]))
    lbt = lower(join("", [local.region, local.env, "lbt", local.tier, local.purpose, local.instance]))

    // Elastic File System
    efs = lower(join("", [local.region, local.env, "efs", local.tier, local.purpose, local.instance]))

    // IAM
    igr = lower(join("", [local.region, local.env, "igr", local.tier, local.purpose, local.instance]))
    ipd = lower(join("", [local.region, local.env, "ipd", local.tier, local.purpose, local.instance]))
    ipl = lower(join("", [local.region, local.env, "ipl", local.tier, local.purpose, local.instance]))
    iro = lower(join("", [local.region, local.env, "iro", local.tier, local.purpose, local.instance]))
    irp = lower(join("", [local.region, local.env, "irp", local.tier, local.purpose, local.instance]))
    usr = lower(join("", [local.region, local.env, "usr", local.tier, local.purpose, local.instance]))

    //kms
    kma = lower(join("", [local.region, local.env, "kma", local.tier, local.purpose, local.instance]))
    kmc = lower(join("", [local.region, local.env, "kmc", local.tier, local.purpose, local.instance]))
    kmk = lower(join("", [local.region, local.env, "kmk", local.tier, local.purpose, local.instance]))
    kmg = lower(join("", [local.region, local.env, "kmg", local.tier, local.purpose, local.instance]))

    //Lambda
    lmb = lower(join("", [local.region, local.env, "lmb", local.tier, local.purpose, local.instance]))
    lmp = lower(join("", [local.region, local.env, "lmp", local.tier, local.purpose, local.instance]))

    // RDS
    rcs = lower(join("", [local.region, local.env, "rcs", local.tier, local.purpose, local.instance]))
    res = lower(join("", [local.region, local.env, "res", local.tier, local.purpose, local.instance]))
    rdi = lower(join("", [local.region, local.env, local.zone, "rdi", local.tier, local.purpose, local.instance])) // Zone explicit
    rda = lower(join("", [local.region, local.env, "rda", local.tier, local.purpose, local.instance]))
    rdo = lower(join("", [local.region, local.env, "rdo", local.tier, local.purpose, local.instance]))
    rdp = lower(join("", [local.region, local.env, "rdp", local.tier, local.purpose, local.instance]))
    rds = lower(join("", [local.region, local.env, "rds", local.tier, local.purpose, local.instance]))
    rdn = lower(join("", [local.region, local.env, "rdn", local.tier, local.purpose, local.instance]))
    rdu = lower(join("", [local.region, local.env, "rdu", local.tier, local.purpose, local.instance]))
    rcc = lower(join("", [local.region, local.env, "rcc", local.tier, local.purpose, local.instance]))
    rce = lower(join("", [local.region, local.env, "rce", local.tier, local.purpose, local.instance]))
    rci = lower(join("", [local.region, local.env, "rci", local.tier, local.purpose, local.instance]))
    rcp = lower(join("", [local.region, local.env, "rcp", local.tier, local.purpose, local.instance]))
    rcg = lower(join("", [local.region, local.env, "rcg", local.tier, local.purpose, local.instance]))

    //Route53
    r5a = lower(join("", [local.region, local.env, "r5a", local.tier, local.purpose, local.instance]))
    r5d = lower(join("", [local.region, local.env, "r5d", local.tier, local.purpose, local.instance]))
    r5h = lower(join("", [local.region, local.env, "r5h", local.tier, local.purpose, local.instance]))
    r5q = lower(join("", [local.region, local.env, "r5q", local.tier, local.purpose, local.instance]))
    r5r = lower(join("", [local.region, local.env, "r5r", local.tier, local.purpose, local.instance]))
    r5z = lower(join("", [local.region, local.env, "r5z", local.tier, local.purpose, local.instance]))

    // S3
    s3b = lower(join("", [local.region, local.env, "s3b", local.tier, local.purpose, local.instance]))
    s3n = lower(join("", [local.region, local.env, "s3n", local.tier, local.purpose, local.instance]))
    s3p = lower(join("", [local.region, local.env, "s3p", local.tier, local.purpose, local.instance]))

    // SageMaker
    smc = lower(join("", [local.region, local.env, "smc", local.tier, local.purpose, local.instance]))
    sme = lower(join("", [local.region, local.env, "sme", local.tier, local.purpose, local.instance]))
    sml = lower(join("", [local.region, local.env, "sml", local.tier, local.purpose, local.instance]))
    smm = lower(join("", [local.region, local.env, "smm", local.tier, local.purpose, local.instance]))
    smn = lower(join("", [local.region, local.env, "smn", local.tier, local.purpose, local.instance]))

    // SES
    sea = lower(join("", [local.region, local.env, "sea", local.tier, local.purpose, local.instance]))
    sei = lower(join("", [local.region, local.env, "sei", local.tier, local.purpose, local.instance]))
    sev = lower(join("", [local.region, local.env, "sev", local.tier, local.purpose, local.instance]))
    sed = lower(join("", [local.region, local.env, "sed", local.tier, local.purpose, local.instance]))
    sef = lower(join("", [local.region, local.env, "sef", local.tier, local.purpose, local.instance]))
    see = lower(join("", [local.region, local.env, "see", local.tier, local.purpose, local.instance]))
    seg = lower(join("", [local.region, local.env, "seg", local.tier, local.purpose, local.instance]))
    ser = lower(join("", [local.region, local.env, "ser", local.tier, local.purpose, local.instance]))
    ses = lower(join("", [local.region, local.env, "ses", local.tier, local.purpose, local.instance]))
    sec = lower(join("", [local.region, local.env, "sec", local.tier, local.purpose, local.instance]))
    sen = lower(join("", [local.region, local.env, "sen", local.tier, local.purpose, local.instance]))
    sep = lower(join("", [local.region, local.env, "sep", local.tier, local.purpose, local.instance]))
    set = lower(join("", [local.region, local.env, "set", local.tier, local.purpose, local.instance]))

    // sns
    sna = lower(join("", [local.region, local.env, "sna", local.tier, local.purpose, local.instance]))
    snc = lower(join("", [local.region, local.env, "snc", local.tier, local.purpose, local.instance]))
    snp = lower(join("", [local.region, local.env, "snp", local.tier, local.purpose, local.instance]))
    snr = lower(join("", [local.region, local.env, "snr", local.tier, local.purpose, local.instance]))
    sns = lower(join("", [local.region, local.env, "sns", local.tier, local.purpose, local.instance]))

    //sqs
    sqs = lower(join("", [local.region, local.env, "sqs", local.tier, local.purpose, local.instance]))

    // VPC
    cgw = lower(join("", [local.region, local.env, "cgw", local.tier, local.purpose, local.instance]))
    cwg = lower(join("", [local.region, local.env, "cwg", local.tier, local.purpose, local.instance]))
    igw = lower(join("", [local.region, local.env, "igw", local.tier, local.purpose, local.instance]))
    ngw = lower(join("", [local.region, local.env, local.zone, "ngw", local.tier, local.purpose, local.instance])) # Zone explicit
    rtb = lower(join("", [local.region, local.env, "rtb", local.tier, local.purpose, local.instance]))
    snt = lower(join("", [local.region, local.env, local.zone, "snt", local.tier, local.purpose, local.instance])) # Zone explicit
    tga = lower(join("", [local.region, local.env, "tga", local.tier, local.purpose, local.instance]))
    tgw = lower(join("", [local.region, local.env, "tgw", local.tier, local.purpose, local.instance]))
    tgr = lower(join("", [local.region, local.env, "tgr", local.tier, local.purpose, local.instance]))
    vpc = lower(join("", [local.region, local.env, "vpc", local.tier, local.purpose, local.instance]))
    vpg = lower(join("", [local.region, local.env, "vpg", local.tier, local.purpose, local.instance]))
    vpn = lower(join("", [local.region, local.env, "vpn", local.tier, local.purpose, local.instance]))
    vpp = lower(join("", [local.region, local.env, "vpp", local.tier, local.purpose, local.instance]))

    // WAF
    waf = lower(join("", [local.region, local.env, "waf", local.tier, local.purpose, local.instance]))
    acl = lower(join("", [local.region, local.env, "acl", local.tier, local.purpose, local.instance]))
    acr = lower(join("", [local.region, local.env, "acr", local.tier, local.purpose, local.instance]))
  }

  // Default Tag Map
  most_tags = merge(var.additional_tags,
    {
      app          = local.app_group
      env          = local.env
      ledger       = local.ledger
      region       = local.region # Renamed from site
      tier         = local.tier
      zone         = local.zone # Zone is still included in tags
      Name         = local.name
      creation_app = "terraform"
    }
  )
  // Allow Purpose to not be included if not set. Some AWS Objects will not allow the set of empty value in a tag set
  tags = local.purpose == "" ? local.most_tags : merge(local.most_tags, { purpose = local.purpose })

  // Provide easy reference for selected type
  name = lookup(local.aws_names, local.type, "unknown_aws_type")

  // Provide standardized logging key prefix for S3 logging
  log_path = join("", [local.log_prefix, "/", local.type, "/", local.name, "/log_"])
}

output "app_group" {
  description = "The resolved application group."
  value       = local.app_group
}

output "env" {
  description = "The resolved environment."
  value       = local.env
}

output "instance" {
  description = "The resolved instance."
  value       = local.instance
}

output "ledger" {
  description = "The resolved ledger."
  value       = local.ledger
}

output "log_prefix" {
  description = "The resolved log prefix."
  value       = local.log_prefix
}

output "purpose" {
  description = "The resolved purpose."
  value       = local.purpose
}

output "region" { # Renamed from site
  description = "The resolved region."
  value       = local.region
}

output "tier" {
  description = "The resolved tier."
  value       = local.tier
}

output "type" {
  description = "The resolved type."
  value       = local.type
}

output "zone" {
  description = "The resolved zone."
  value       = local.zone
}

output "name" {
  description = "The generated resource name based on the naming convention."
  value       = local.name
}

output "tags" {
  description = "The generated tags for the resource."
  value       = local.tags
}

output "log_path" {
  description = "The generated log path for S3 logging."
  value       = local.log_path
}
