FROM gr0wvolution/webfluid:beta
COPY constraints.txt /tmp/peer-constraints.txt
RUN pip install --no-cache-dir --upgrade -r /tmp/peer-constraints.txt wf-peering==1.0a1
