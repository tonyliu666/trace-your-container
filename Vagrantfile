Vagrant.configure("2") do |config|

    # Base box for Ubuntu 22.04
    config.vm.box = "ubuntu/jammy64"
    
    # Set VM resources (optional)
    config.vm.provider "virtualbox" do |vb|
      vb.memory = "4096"
      vb.cpus = 4
    end

    config.vm.provision "shell", inline: <<-SHELL
      # Update package list again after reboot
      sudo apt-get update
  
      # Install prerequisites for Docker
      sudo apt-get install -y apt-transport-https ca-certificates curl software-properties-common
  
      # Add Docker’s official GPG key
      curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo gpg --dearmor -o /usr/share/keyrings/docker-archive-keyring.gpg
  
      # Set up the stable repository
      echo "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/docker-archive-keyring.gpg] https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable" | sudo tee /etc/apt/sources.list.d/docker.list > /dev/null
  
      # Install Docker
      sudo apt-get update
      sudo apt-get install -y docker-ce docker-ce-cli containerd.io
  
      # Start Docker and enable it to run on startup
      sudo systemctl start docker
      sudo systemctl enable docker
  
      # Add the vagrant user to the docker group
      sudo usermod -aG docker vagrant
    SHELL
  
    # Provisioning script for the kernel update
    config.vm.provision "shell", inline: <<-SHELL
      # Update the package list
      sudo apt-get update
      
      # Install necessary tools and headers
      sudo apt-get install -y linux-headers-6.8.0-48-generic linux-image-6.8.0-48-generic
      
      # Set kernel 6.8.0-48 as the default
      sudo grub-set-default 0
      sudo update-grub
      
      # Reboot to apply the new kernel
      sudo reboot
    SHELL
    
  end