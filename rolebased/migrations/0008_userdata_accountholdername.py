# Generated by Django 4.0.6 on 2023-12-25 09:48

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('rolebased', '0007_userdata'),
    ]

    operations = [
        migrations.AddField(
            model_name='userdata',
            name='accountHolderName',
            field=models.CharField(blank=True, max_length=50, null=True),
        ),
    ]