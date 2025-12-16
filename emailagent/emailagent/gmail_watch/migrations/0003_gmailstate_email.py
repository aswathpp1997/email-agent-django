# Generated manually
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('gmail_watch', '0002_gmailoauthtoken'),
    ]

    operations = [
        migrations.AddField(
            model_name='gmailstate',
            name='email',
            field=models.EmailField(db_index=True, default='', max_length=254, unique=True),
            preserve_default=False,
        ),
        migrations.RemoveField(
            model_name='gmailstate',
            name='id',
        ),
        migrations.AlterField(
            model_name='gmailstate',
            name='email',
            field=models.EmailField(db_index=True, max_length=254, primary_key=True, serialize=False, unique=True),
        ),
        migrations.AlterModelTable(
            name='gmailstate',
            table='gmail_state',
        ),
    ]

