import json
import demistomock as demisto
import pytest


def util_open_file(path):
    with open(path, mode='r') as f:
        return f.read()


def util_load_json(path):
    with open(path, mode='r') as f:
        return json.loads(f.read())



EMAIL_HTML = """
<html><head><meta http-equiv="Content-Type" content="text/html; charset=utf-8"></head><body><div dir="ltr">image 1:
<div><div><img src="cid:ii_kgjzy6yh0" alt="image_1.png" width="275" height="184"><br></div></div><div>image 2:
</div><div><div><img src="cid:ii_kgjzygxz1" alt="image_2.png" width="225" height="224"><br></div></div></div><br>
<div class="gmail_quote"><div dir="ltr" class="gmail_attr">On Thu, Oct 22, 2020 at 1:56 AM Avishai Brandeis &lt;
<a href="mailto:avishai@demistodev.onmicrosoft.com">avishai@demistodev.onmicrosoft.com</a>&gt; wrote:<br></div>
<blockquote class="gmail_quote" style="margin: 0px 0px 0px 0.8ex;border-left:1px solid rgb(204,204,204)"><u></u><div>
<p>please add multiple inline images</p></div></blockquote></div></body></html>"""

EXPECTED_RESULT_1 = """
<html><head><meta http-equiv="Content-Type" content="text/html; charset=utf-8"></head><body><div dir="ltr">image 1:
<div><div><img src=entry/download/37@119  alt="image_1.png" width="275" height="184"><br></div></div><div>image 2:
</div><div><div><img src=entry/download/38@120  alt="image_2.png" width="225" height="224"><br></div></div></div><br>
<div class="gmail_quote"><div dir="ltr" class="gmail_attr">On Thu, Oct 22, 2020 at 1:56 AM Avishai Brandeis &lt;
<a href="mailto:avishai@demistodev.onmicrosoft.com">avishai@demistodev.onmicrosoft.com</a>&gt; wrote:<br></div>
<blockquote class="gmail_quote" style="margin: 0px 0px 0px 0.8ex;border-left:1px solid rgb(204,204,204)"><u></u><div>
<p>please add multiple inline images</p></div></blockquote></div></body></html>"""

EXPECTED_RESULT_2 = """
<html><head><meta http-equiv="Content-Type" content="text/html; charset=utf-8"></head><body><div dir="ltr">image 1:
<div><div><img src=acc_test_tenant/entry/download/37@119  alt="image_1.png" width="275" height="184"><br></div></div><div>image 2:
</div><div><div><img src=acc_test_tenant/entry/download/38@120  alt="image_2.png" width="225" height="224"><br></div></div></div><br>
<div class="gmail_quote"><div dir="ltr" class="gmail_attr">On Thu, Oct 22, 2020 at 1:56 AM Avishai Brandeis &lt;
<a href="mailto:avishai@demistodev.onmicrosoft.com">avishai@demistodev.onmicrosoft.com</a>&gt; wrote:<br></div>
<blockquote class="gmail_quote" style="margin: 0px 0px 0px 0.8ex;border-left:1px solid rgb(204,204,204)"><u></u><div>
<p>please add multiple inline images</p></div></blockquote></div></body></html>"""


@pytest.mark.parametrize(
    "email_html,entry_id_list,expected",
    [
     (EMAIL_HTML, [('image_1.png', '37@119'), ('image_2.png', '38@120')], EXPECTED_RESULT_1)]
)
def test_create_email_html(email_html, entry_id_list, expected):
    """
        Given
        - The email's Html representation.
        When
        3. All images were uploaded to the server.
        Then
        - The images' src attribute would be replaced as expected.
    """
    from DisplayEmailHtml import create_email_html
    result = create_email_html(email_html, entry_id_list)
    assert result == expected

@pytest.mark.parametrize(
    "email_html,entry_id_list,expected",
    [
     (EMAIL_HTML, [('image_1.png', '37@119'), ('image_2.png', '38@120')], EXPECTED_RESULT_2)]
)
def test_create_email_html_mt(mocker, email_html, entry_id_list, expected):
    """
        Given
        - The email's Html representation.
        When
        - All images were uploaded to the server.
        Then
        - The images' src attribute would be replaced as expected with account tenant name
    """
    from DisplayEmailHtml import create_email_html
    mocker.patch.object(demisto, 'demistoUrls', return_value={'server': 'https://localhost:8443:/acc_test_tenant'})

    result = create_email_html(email_html, entry_id_list)
    assert result == expected
