# Machine Learning Security Evasion Competition 2022
## Introduction
The [Machine Learning Security Evasion Competition (MLSEC) 2022](https://mlsec.io/) took place from August 12th to September 23th 2022 and was organized by [Adversa AI](https://adversa.ai/), [CUJO AI](https://cujo.com/), and [Robust Intelligence](https://www.robustintelligence.com/).
This was for me the first security comptetition tageting ML systems and so I was very motivated to take part in it. Overall, such competitions great opportunities to do practice, meet new people and, why not, try to win the first prize :).
By the way, I took part in the Anti-Phishing Evasion challenge and achieved the first place.
In the follow, I will first introduce the challenge and then explain my solution.

## Anti-Phishing Evasion challenge
The goal of the challenge was to manipulate 10 phishing web pages (HTML files) in order to evade 8 ML models (for a total of 80 points), which have been designed to detect phishing web pages. A ML model is considered evaded if the returned output probability score (of being a phishing sample) is lower than `0.1`. The challenge had an additional constraint: the manipulated web page must be rendered in the same way as the original one. In practice, this means that the screenshots of the (rendered) manipulated and original web page must have the same (SHA-256) hash.

## Solution
The core idea behind the solution is: starting from the original phishing web page, manipulate it by injecting some HTML elements such that the classification score returned by the ML classifiers is below the threshold (i.e., the ML models are evaded). The new manipulated web page can be seen as an _adversarial example_ for the target ML models.
This approach is similar to the one adopted to evade ML-based malware detectors (see [Adversarial EXEmple by Demetrio et al.](https://arxiv.org/abs/2008.07125)). It basically consists in defining:
- a set of manipulations that represent how to manipulate an input sample. It is important to point out that such manipulations must be functionality-preserving, that is they must preserve the original behavior/semantic (for example, in our case the manipulated web page must be successfully rendered as the original one).
- a strategy (also known as "optimizer") that specifies how to apply the manipulations.

### **Manipulations**
Considering our problem, the manipulations are represented by the injection of HTML elements. So, **the main point to address was finding successful manipulations, that is manipulations to which the ML models are sensitive and can be exploited in order to evade the ML model**.
Unfortunately, when operating on data like malware (PE files) or web pages (HTML files), the set of possible manipulations is quite huge (i.e., the input space is very big) and usually an extensive testing is needed.
Anyway, after experimenting a bit (see the Appendinx section to know more about experiments I did before finding the successful manipulations), I found out that adding several `<input>` tags of certain types such as `text`, `submit`, `radio`, `search` and `button` in the body of the web page allowed me to decrease the classification score below the threshold.
Anyway, the addition of such `<input>` tags causes the manipulated web page to have a different rendering, thus violating the constraint of the challenge.
To solve this issue, the added `<input>` tags can be embedded into `<noscript></noscript>`. In this way, everything included in `<noscript></noscript>` is basically ignored (I verified that the sandbox hosted for the challenge had a Web browser with JS enabled).
However, the ML models are still sensitive to the injected HTML tags because, considering the results obtained during testing, they are used in the feature extraction phase (the ML models do not check whether the injected HTML tags are nested into `<noscript></noscript>`) causing the ML models to be fooled.
Moreover, by performing further testing I also found additional manipulations that resulted effective in decreasing the confidence score:
- Changing the type of `password` `<input>` tags to `text` (like in `<input type="password" .../>` ⟶ `<input type="text" .../>`).
- Adding random JS code nested in `<noscript></noscript>` into the `<head>` and `<body>` of the sample web pages.
- Moving the CSS code from the `<head>` to the `<body>` (especially for those web pages with a lot of CSS code).

### **Strategies**
Withouth knowing a-priori which are "successful" HTML elements (tags) to inject, the basic approach consists in trying adding the most common HTML tags (one by one) and using the API provided by the competition to get the classification scores.  
Then, if the score is reduced, we need to ensure that the rendering is preserved before injecting additional tags of the same type (to check whether increasing the number of the previously added tags futher reduces the score) or try a different type.  
Otherwise, it means that the added HTML element is not effective in decreasing the score. So remove it and try a new one of different a type.  
Moreover, in this competition I found particularly useful to inject some copies of the same tag instead of a single one to speed up the evasion.
By following this approach, I was able to find the HTML tags (described above) that shown to be effective in bypassing the ML models.

From an implementation point of view, the above idea can be refined by creating a fuzzer that iteratively tries inserting different types of HTML tags one at time and by keeping track of the returned score in order to decide whether to keep the injected tag (or a set of equal tags) or to remove it. If implementing the fuzzer in Python, the HTML page can be easily manipulated using [beautifulsoup](https://beautiful-soup-4.readthedocs.io/en/latest/) library.

Finally, in order to check whether the rendering is preserved, I used the following Python script, which makes use of [html2image](https://github.com/vgalin/html2image) to take a screenshot when rendering a web page:
```python
import os
import hashlib
from PIL import Image
from html2image import Html2Image

adversarial_pages_path = os.path.abspath(".")
phising_files_path = os.path.abspath("..")

def check_rendering(selected_samples=None, remove_screenshots=False):
    hti = Html2Image()
    if selected_samples is not None:
        assert(isinstance(selected_samples, list) and 1 <= len(selected_samples) <= 10 and
               all([1 <= s <= 10 for s in selected_samples]))
    files_idx = selected_samples if selected_samples is not None else list(range(1, 11))
    check_list = ['{:02d}'.format(idx) for idx in files_idx]

    for img_name in check_list:
        # save a screenshot of both the original and modified web pages
        hti.screenshot(html_file=os.path.join(phising_files_path, img_name + '.html'),
                       save_as=img_name + '.png')
        hti.screenshot(html_file=os.path.join(adversarial_pages_path, img_name + '.html'),
                       save_as=img_name + '_adv.png')

        # compute the SHA-256 hashes
        hash_original = hashlib.sha256(Image.open(img_name + '.png').tobytes()).hexdigest()
        hash_adv = hashlib.sha256(Image.open(img_name + '_adv.png').tobytes()).hexdigest()

        if hash_original == hash_adv:
            print("The original html and the generated adversarial example " +
                  "have the same rendering!\n")
        else:
            print("The original html and the generated adversarial example do NOT " +
                  "have the same rendering!.\nDifferent SHA256 hashes: " +
                  "{}\n{}\n".format(hash_original, hash_adv))

        if remove_screenshots:
            os.remove(img_name + '.png')
            os.remove(img_name + '_adv.png')

if __name__ == "__main__":
    # check_rendering()
    # pass a list of intgers (from 1 to 10) to select specific web pages
    check_rendering(selected_samples=[1, 3, 8])
```

## Closing remarks
Special thanks to all the organizers of the competition as well as kudos to all the people who participated into the challenge. Overall, it was a great experience!