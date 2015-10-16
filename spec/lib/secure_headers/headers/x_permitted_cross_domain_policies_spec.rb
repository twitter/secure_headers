module SecureHeaders
  describe XPermittedCrossDomainPolicies do
    specify { expect(XPermittedCrossDomainPolicies.make_header).to eq([XPermittedCrossDomainPolicies::HEADER_NAME, "none"])}
    specify { expect(XPermittedCrossDomainPolicies.make_header('master-only')).to eq([XPermittedCrossDomainPolicies::HEADER_NAME, 'master-only'])}

    context "valid configuration values" do
      it "accepts 'all'" do
        expect {
          XPermittedCrossDomainPolicies.validate_config!("all")
        }.not_to raise_error
      end

      it "accepts 'by-ftp-filename'" do
        expect {
          XPermittedCrossDomainPolicies.validate_config!("by-ftp-filename")
        }.not_to raise_error
      end

      it "accepts 'by-content-type'" do
        expect {
          XPermittedCrossDomainPolicies.validate_config!("by-content-type")
        }.not_to raise_error
      end
      it "accepts 'master-only'" do
        expect {
          XPermittedCrossDomainPolicies.validate_config!("master-only")
        }.not_to raise_error
      end

      it "accepts nil" do
        expect {
          XPermittedCrossDomainPolicies.validate_config!(nil)
        }.not_to raise_error
      end
    end

    context 'invlaid configuration values' do
      it "doesn't accept invalid values" do
        expect {
          XPermittedCrossDomainPolicies.validate_config!("open")
        }.to raise_error(XPCDPConfigError)
      end
    end
  end
end
