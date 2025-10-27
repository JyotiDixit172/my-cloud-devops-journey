from flask import Flask, render_template_string, request
import boto3

app = Flask(__name__)

# Available instance types
INSTANCE_TYPES = ["t2.micro", "t2.small", "t3.micro", "t3.medium"]

# Global variable to track created instance
CREATED_INSTANCE_ID = None

HTML_FORM = """
<!doctype html>
<title>AWS EC2 Creator with Boto3</title>
<h2>AWS VM Automation (Boto3)</h2>
<form method="POST">
<label for="instance">Select VM Instance Type:</label>
<select name="instance">
{% for itype in instance_types %}
<option value="{{ itype }}">{{ itype }}</option>
{% endfor %}
</select>
<br><br>
<button type="submit" name="action" value="create">✅ Create VM</button>
<button type="submit" name="action" value="destroy">❌ Destroy VM</button>
</form>
{% if message %}
<h3>{{ message|safe }}</h3>
{% endif %}
"""

# Create EC2 client
ec2 = boto3.resource("ec2", region_name="us-east-1")

@app.route("/", methods=["GET", "POST"])
def index():
global CREATED_INSTANCE_ID
message = ""

if request.method == "POST":
action = request.form["action"]

if action == "create":
instance_type = request.form["instance"]
try:
instances = ec2.create_instances(
ImageId="ami-08c40ec9ead489470", # Amazon Linux 2 AMI (update if region differs)
MinCount=1,
MaxCount=1,
InstanceType=instance_type,
KeyName="my-keypair", # must exist in your AWS account
SecurityGroups=["default"] # must exist in your AWS account
)
instance = instances[0]
CREATED_INSTANCE_ID = instance.id

# Wait until running
instance.wait_until_running()

# Reload to get public IP
instance.load()

message = f"✅ VM Created: <br> ID: {instance.id} <br> Type: {instance.instance_type} <br> Public IP: {instance.public_ip_address}"
except Exception as e:
message = f"❌ Error creating VM: {e}"

elif action == "destroy":
if CREATED_INSTANCE_ID:
try:
instance = ec2.Instance(CREATED_INSTANCE_ID)
instance.terminate()
instance.wait_until_terminated()
message = f"🗑️ VM {CREATED_INSTANCE_ID} destroyed successfully."
CREATED_INSTANCE_ID = None
except Exception as e:
message = f"❌ Error destroying VM: {e}"
else:
message = "⚠️ No VM found to destroy."

return render_template_string(HTML_FORM, instance_types=INSTANCE_TYPES, message=message)


if __name__ == "__main__":
app.run(debug=True)