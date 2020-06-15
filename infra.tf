//credentials
provider "aws" {
	region  ="ap-south-1"
	profile ="rishabh_ec2"
}



//creates a public-private key pair
resource "tls_private_key" "local_Key" {
    algorithm = "RSA"
}


//saves the private key to a file for connecting afterwards
resource "local_file" "pvt_key" {
content = tls_private_key.local_Key.private_key_pem
filename ="task.pem"
file_permission = 0400
}



//deploys key to aws
resource "aws_key_pair" "deployer" {
key_name = "pub_key"
public_key = tls_private_key.local_Key.public_key_openssh
}


//security group to allow port 22 and 80
resource "aws_security_group" "allow_traffic" {
  name        = "allow_traffic"
  description = "Allow inbound traffic"

  ingress {
    description = "inbound web traffic"
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    description = "inbound ssh"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "allow inbound"
  }
}



//instance creation
resource "aws_instance" "server" {
  ami           = "ami-052c08d70def0ac62"
  instance_type = "t2.micro"
  availability_zone = "ap-south-1a"
  key_name      = "pub_key"
  security_groups = ["${aws_security_group.allow_traffic.name}"]

  tags = {
      Name = "terraform_task"
    }
}




//creation of ebs volume
resource "aws_ebs_volume" "mypd" {
  availability_zone = "ap-south-1a"
  size              = 2
  
  tags = {
    Name = "mypd"
  }
}



//attaching ebs volume to the ec2 instance
resource "aws_volume_attachment" "pd_att" {

  depends_on = [
    aws_ebs_volume.mypd, aws_instance.server,
  ]

  device_name = "/dev/sdn"
  volume_id   = aws_ebs_volume.mypd.id
  instance_id = aws_instance.server.id
  force_detach = true
}



resource "null_resource" "nullremote"  {

depends_on = [
    aws_volume_attachment.pd_att, 
 ]
  

  //conecting to the instance
  connection {
    type     = "ssh"
    user     = "ec2-user"
    private_key = tls_private_key.local_Key.private_key_pem
    host     = aws_instance.server.public_ip
  }


  //executing commands in instance
  provisioner "remote-exec" {
    inline = [
        "sudo yum install httpd -y",
        "sudo systemctl start httpd",
        "sudo systemctl enable httpd",
        "sudo yum install git -y",
        "sudo setenforce 0",
        "sudo mkfs.ext4  /dev/xvdn",
        "sudo mount  /dev/xvdn  /var/www/html",
        "sudo rm -rf /var/www/html/*",
        "sudo git clone https://github.com/mccaurtney87/HCtask1_utilities.git  /var/www/html"
    ]
  }
}



//creating s3 bucket
resource "aws_s3_bucket" "bkt" {

  depends_on = [
    aws_volume_attachment.pd_att,
  ]

  bucket = "bhaikabucket80"
  acl    = "public-read"
  force_destroy = true

  //copying the image from github to local system
  provisioner "local-exec" {
        command     = "git clone https://github.com/mccaurtney87/HCtask1_utilities.git server_img"
    }

    provisioner "local-exec" {
        when        =   destroy
        command     =   "rmdir /s /q server_img"
    }
}



//uploading the image to bucket
resource "aws_s3_bucket_object" "upload" {

    depends_on = [
    aws_s3_bucket.bkt,
  ]
  
  bucket  = aws_s3_bucket.bkt.bucket
  key     = "happiness.jpg"
  source  = "server_img/doggo.jpg"
  acl     = "public-read"
}



locals {
  s3_origin_id = "S3-${aws_s3_bucket.bkt.bucket}"
}


//creating cloudfront CDN service
resource "aws_cloudfront_distribution" "meraCDN" {
  
  origin {
    domain_name = aws_s3_bucket.bkt.bucket_regional_domain_name
    origin_id   = local.s3_origin_id 

    custom_origin_config {
      http_port = 80
      https_port = 80
      origin_protocol_policy = "match-viewer"
      origin_ssl_protocols = ["TLSv1", "TLSv1.1", "TLSv1.2"]
    }
  }

  enabled = true
  is_ipv6_enabled = true

  default_cache_behavior {
    allowed_methods = [ "GET", "HEAD", "OPTIONS", "DELETE", "PATCH", "POST", "PUT"]
    cached_methods = ["GET", "HEAD"]
    target_origin_id = local.s3_origin_id

    viewer_protocol_policy = "allow-all"
    min_ttl = 0
    default_ttl = 3600
    max_ttl = 86400

    forwarded_values {
        query_string = false

        cookies {
        forward = "none"
        }
    }
  }
  

  restrictions {
    geo_restriction {
      restriction_type = "none"
    }
  }

  viewer_certificate {
    cloudfront_default_certificate = true
  }

  connection {
    type     = "ssh"
    user     = "ec2-user"
    private_key = tls_private_key.local_Key.private_key_pem
    host     = aws_instance.server.public_ip
  }


  provisioner "remote-exec" {
        
        inline = [
          "sudo su << EOF",
          "echo \"<img src='http://${self.domain_name}/${aws_s3_bucket_object.upload.key}'>\" | sudo tee -a /var/www/html/index.html",
          "EOF"
        ]
    }
}



resource "null_resource" "nulllocal"  {


depends_on = [
    null_resource.nullremote,aws_cloudfront_distribution.meraCDN
  ]

	provisioner "local-exec" {
	    command = " start chrome  ${aws_instance.server.public_ip}"
  	     }
}
