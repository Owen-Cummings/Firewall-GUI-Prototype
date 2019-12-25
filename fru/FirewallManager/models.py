from django.db import models
from django.contrib.auth.models import User
from django.db.models.signals import post_save
from django.dispatch import receiver
from phonenumber_field.modelfields import PhoneNumberField

# Firewall Rule class
# Rule format: ufw <permission> proto <protocol> from <ip/subnet> to <ip> port <port#>
class Rule(models.Model):

	PERMISSION_OPTIONS = (
		('a', 'allow'),
		('d', 'deny'),
	)

	permission = models.CharField(
		max_length=1, 
		choices=PERMISSION_OPTIONS 
	)
	protocol = models.CharField(max_length=3)
	from_ip = models.CharField(max_length=18)
	to_ip = models.GenericIPAddressField()
	port_number = models.IntegerField()

	def __str__(self):
		return f'{self.id} ufw {self.permission} proto {self.protocol} from {self.from_ip} to {self.to_ip} port {self.port_number}'

# Extending the User class to add phone number
class Profile(models.Model):
	user = models.OneToOneField(User, on_delete=models.CASCADE)
	phone_number = PhoneNumberField()

@receiver(post_save, sender=User)
def create_profile(sender, instance, created, **kwargs):
    if created:
        Profile.objects.create(user=instance)

@receiver(post_save, sender=User)
def save_profile(sender, instance, **kwargs):
    instance.profile.save()
