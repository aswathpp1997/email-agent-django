# Generated manually
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('gmail_watch', '0001_initial'),
    ]

    operations = [
        migrations.CreateModel(
            name='GmailOAuthToken',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('email', models.EmailField(db_index=True, max_length=254, unique=True)),
                ('access_token', models.TextField()),
                ('refresh_token', models.TextField(blank=True, null=True)),
                ('token_expires_at', models.DateTimeField(blank=True, null=True)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('updated_at', models.DateTimeField(auto_now=True)),
            ],
            options={
                'verbose_name': 'Gmail OAuth Token',
                'verbose_name_plural': 'Gmail OAuth Tokens',
                'db_table': 'gmail_oauth_tokens',
            },
        ),
    ]

